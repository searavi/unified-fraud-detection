"""
Investigation Service

Manages fraud investigations using the Synktron Mesh workflow.
Provides SSE streaming for real-time investigation progress.
"""

import asyncio
import json
import os
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, AsyncGenerator, Optional

import docker
import httpx


def create_initial_state(investigation_id: str, user_id: str) -> Dict[str, Any]:
    """Minimal initial InvestigationState written to Aerospike KV before Mesh runs."""
    return {
        "investigation_id": investigation_id,
        "user_id": user_id,
        "started_at": datetime.now().isoformat(),
        "alert_evidence": None,
        "initial_evidence": None,
        "agent_messages": [],
        "tool_calls": [],
        "tool_results": {},
        "agent_iterations": 0,
        "final_assessment": None,
        "report_markdown": "",
        "current_phase": "alert_validation",
        "current_node": "start",
        "workflow_status": "running",
        "error_message": None,
        "trace_events": [],
    }

logger = logging.getLogger('investigation.service')

MESH_BASE_URL = os.environ.get("MESH_BASE_URL", "http://synktron-meshruntime-local:8080")

WORKFLOW_MANIFEST = {
    "manifest": {
        "tasks": [
            {"agentId": "alert_validation",  "order": 1, "name": "Alert Validation",  "isCritical": True},
            {"agentId": "data_collection",   "order": 2, "name": "Data Collection",   "isCritical": True},
            {"agentId": "llm_agent",         "order": 3, "name": "LLM Investigation", "isCritical": True},
            {"agentId": "report_generation", "order": 4, "name": "Report Generation", "isCritical": True},
        ]
    }
}

WORKFLOW_STEPS = [
    {"id": "alert_validation",  "name": "Alert Validation",  "description": "Extracting alert context"},
    {"id": "data_collection",   "name": "Data Collection",   "description": "Gathering evidence"},
    {"id": "llm_investigation", "name": "LLM Investigation", "description": "AI fraud analysis"},
    {"id": "report_generation", "name": "Report Generation", "description": "Generating report"},
]

STEP_NAMES = ["alert_validation", "data_collection", "llm_investigation", "report_generation"]

# Mesh reports HITL/policy outcomes via the response body's errorCode, not the HTTP status —
# a 200 can carry status="Failed" or "AwaitingApproval". Mesh's own `error` text is already a
# clear sentence for each of these; just label it with a short, code-derived category.
MESH_HITL_ERROR_LABELS = {
    "hitl_policy_missing": "No HITL policy configured",
    "hitl_policy_denied": "HITL policy denied",
    "MESH_HITL_APPROVAL_REQUIRED": "Awaiting human approval",
}

# The local Mesh/OPA sidecar (test-container-locally.ps1) runs OPA in file-mount mode: it reads
# this file once at container start and has no bundle-service config, so it never polls Mesh's
# HITL policy API (PUT /api/v1/hitl/policies/{tenantId} would write to Azure Blob storage this
# OPA never looks at). The only way to change what it enforces is to edit this file directly and
# restart the container so OPA re-reads it.
OPA_POLICY_FILE = os.environ.get("OPA_POLICY_FILE", "/opa-policies/data.json")
OPA_CONTAINER_NAME = os.environ.get("OPA_CONTAINER_NAME", "opa-sidecar-local-test")
# A restart, not a poll interval — OPA re-reads the file on boot, so a few seconds covers
# container stop/start; there is nothing to "propagate" beyond that.
OPA_RESTART_WAIT_SECONDS = 5

PERMISSIVE_POLICY_DATA = {
    "permissive_mode": True,
    "workflow_policies": [],
    "agent_policies": [],
    "executor_groups": [],
    "executor_roles": [],
    "approver_groups": [],
    "approver_roles": [],
    "workflow_approvals": {},
    "agent_approvals": {},
}


class InvestigationService:
    """
    Service for managing fraud investigations via Synktron Mesh.
    """

    def __init__(
        self,
        aerospike_service: Any,
        graph_service: Any,
        **kwargs  # absorb legacy ollama_base_url / ollama_model args
    ):
        self.aerospike_service = aerospike_service
        self.graph_service = graph_service
        self._mesh_base_url = MESH_BASE_URL
        self._mesh_workflow_id: Optional[str] = None
        self._mesh_client = httpx.AsyncClient(timeout=300.0)
        self._active_investigations: Dict[str, Dict[str, Any]] = {}
        self._investigation_results: Dict[str, Dict[str, Any]] = {}
        logger.info(f"Investigation service initialized — Mesh at {self._mesh_base_url}")

    async def _mesh_auth_header(self) -> Dict[str, str]:
        """Fetch (or reuse) a local-dev bearer token for authenticated Mesh calls.

        Mesh's workflow endpoints require JWT claims (ExtractHitlContextFromClaims) —
        an unauthenticated call gets a 401. The /local/token endpoint is
        [AllowAnonymous] and non-production only, matching this local Docker setup.
        """
        response = await self._mesh_client.get(
            f"{self._mesh_base_url}/api/v1/mesh/security/local/token",
        )
        response.raise_for_status()
        token = response.json()["token"]
        return {"Authorization": f"Bearer {token}"}

    async def initialize(self):
        """Register workflow manifest with Mesh and store the workflow ID."""
        try:
            self._mesh_workflow_id = await self._create_mesh_workflow()
            logger.info(f"Mesh workflow registered: {self._mesh_workflow_id}")
        except Exception as e:
            logger.error(f"Failed to initialize investigation service: {e}")
            raise

    async def _create_mesh_workflow(self) -> str:
        """POST AgentManifest to Mesh and return the workflowId."""
        headers = await self._mesh_auth_header()
        response = await self._mesh_client.post(
            f"{self._mesh_base_url}/api/workflow/create",
            json=WORKFLOW_MANIFEST,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        workflow_id = (
            data.get("workflowId")
            or data.get("id")
            or data.get("manifest", {}).get("id")
        )
        if not workflow_id:
            raise ValueError(f"Mesh did not return a workflowId: {data}")
        return workflow_id

    async def enable_workflow_policy_and_wait(self) -> Dict[str, Any]:
        """Flip the local OPA sidecar to permissive mode and restart it so the change takes
        effect. This OPA runs in file-mount mode (test-container-locally.ps1): it reads
        OPA_POLICY_FILE once at container start and has no bundle-service config, so it never
        polls Mesh's HITL policy API — a container restart, not a propagation wait, is what
        actually applies a new policy here.

        Returns {"success": bool, "verified": bool, "message": str}.
        """
        try:
            with open(OPA_POLICY_FILE, "w") as f:
                json.dump(PERMISSIVE_POLICY_DATA, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to write OPA policy file {OPA_POLICY_FILE}: {e}")
            return {"success": False, "verified": False, "message": f"Failed to write policy file: {e}"}

        try:
            client = await asyncio.to_thread(docker.from_env)
            container = await asyncio.to_thread(client.containers.get, OPA_CONTAINER_NAME)
            await asyncio.to_thread(container.restart, timeout=10)
        except docker.errors.NotFound:
            logger.error(f"OPA container '{OPA_CONTAINER_NAME}' not found")
            return {
                "success": False,
                "verified": False,
                "message": f"OPA container '{OPA_CONTAINER_NAME}' not found — is Mesh running?",
            }
        except docker.errors.DockerException as e:
            logger.error(f"Failed to restart OPA container '{OPA_CONTAINER_NAME}': {e}")
            return {"success": False, "verified": False, "message": f"Failed to restart OPA: {e}"}

        logger.info(
            f"OPA container '{OPA_CONTAINER_NAME}' set to permissive mode and restarted — "
            f"waiting {OPA_RESTART_WAIT_SECONDS}s for it to come back up"
        )
        await asyncio.sleep(OPA_RESTART_WAIT_SECONDS)

        try:
            await asyncio.to_thread(container.reload)
            running = container.status == "running"
        except docker.errors.DockerException as e:
            logger.error(f"Failed to verify OPA container status: {e}")
            return {
                "success": True,
                "verified": False,
                "message": f"Policy file updated and OPA restart requested, but could not confirm it came back up: {e}",
            }

        if running:
            return {"success": True, "verified": True, "message": "OPA is now running in permissive mode."}
        return {
            "success": True,
            "verified": False,
            "message": f"Policy file updated, but OPA container is not running (status: {container.status}).",
        }

    async def close(self):
        """Clean up resources."""
        await self._mesh_client.aclose()
        logger.info("Investigation service closed")

    def get_workflow_steps(self) -> list[Dict[str, str]]:
        return WORKFLOW_STEPS

    async def start_investigation(
        self,
        user_id: str,
        triggered_by: str = "manual"
    ) -> str:
        investigation_id = f"inv_{uuid.uuid4().hex[:12]}"
        self._active_investigations[investigation_id] = {
            "user_id": user_id,
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "triggered_by": triggered_by,
            "current_step": "alert_validation",
        }
        logger.info(f"Started investigation {investigation_id} for user {user_id}")
        return investigation_id

    async def stream_investigation(
        self,
        user_id: str,
        investigation_id: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        if not investigation_id:
            investigation_id = await self.start_investigation(user_id)

        if not self._mesh_workflow_id:
            await self.initialize()

        # SSE start event
        yield {
            "event": "start",
            "data": {
                "investigation_id": investigation_id,
                "user_id": user_id,
                "steps": self.get_workflow_steps(),
            },
        }

        try:
            # Write initial InvestigationState to Aerospike KV so agents can read it
            initial_state = create_initial_state(investigation_id, user_id)
            if self.aerospike_service and self.aerospike_service.is_connected():
                self.aerospike_service.put_investigation(investigation_id, dict(initial_state))
                logger.info(f"Initial state written for {investigation_id}")

            # Launch Mesh workflow execution as background task
            mesh_headers = await self._mesh_auth_header()
            execute_task = asyncio.create_task(
                self._mesh_client.post(
                    f"{self._mesh_base_url}/api/workflow/{self._mesh_workflow_id}/execute",
                    json={
                        "goal": "investigate",
                        "inputs": {
                            "investigation_id": investigation_id,
                            "user_id": user_id,
                        },
                    },
                    headers=mesh_headers,
                )
            )

            # POST {workflowId}/execute blocks until the workflow finishes (or pauses on HITL),
            # so there's no run id to poll status against while it's in flight — Mesh only
            # returns WorkflowExecutionId in the response body once execute_task completes.
            # Just wait for it; remaining progress steps are emitted below in one burst.
            emitted_steps = 0
            while not execute_task.done():
                await asyncio.sleep(2)

            # Collect Mesh response
            mesh_resp = execute_task.result()
            mesh_resp.raise_for_status()
            mesh_body = mesh_resp.json()

            # Mesh reports HITL/policy outcomes in the body, not the HTTP status — a 200 can carry
            # status="Failed" (errorCode "hitl_policy_missing"/"hitl_policy_denied") or
            # "AwaitingApproval" (errorCode "MESH_HITL_APPROVAL_REQUIRED", Gate 4/5 paused for a
            # human). Only "Completed" means the agents actually ran.
            mesh_status = mesh_body.get("status")
            if mesh_status != "Completed":
                error_code = mesh_body.get("errorCode")
                reason = mesh_body.get("error") or mesh_body.get("message") or "Unknown Mesh failure"
                label = MESH_HITL_ERROR_LABELS.get(error_code)
                error_message = f"{label}: {reason}" if label else reason

                logger.error(
                    f"Investigation {investigation_id} blocked by Mesh — status={mesh_status} "
                    f"errorCode={error_code}: {error_message}"
                )
                yield {
                    "event": "investigation_error",
                    "data": {
                        "error": error_message,
                        "errorCode": error_code,
                        "investigation_id": investigation_id,
                    },
                }
                if investigation_id in self._active_investigations:
                    status_label = "awaiting_approval" if mesh_status == "AwaitingApproval" else "blocked"
                    self._active_investigations[investigation_id]["status"] = status_label
                    self._active_investigations[investigation_id]["error"] = error_message
                return

            mesh_run_id = mesh_body.get("workflowExecutionId")
            if mesh_run_id and investigation_id in self._active_investigations:
                self._active_investigations[investigation_id]["mesh_run_id"] = mesh_run_id

            # Emit any remaining progress steps
            while emitted_steps < len(STEP_NAMES):
                yield {
                    "event": "progress",
                    "data": {
                        "node": STEP_NAMES[emitted_steps],
                        "phase": STEP_NAMES[emitted_steps],
                    },
                }
                emitted_steps += 1

            # Read final InvestigationState from Aerospike KV
            final_state = None
            if self.aerospike_service and self.aerospike_service.is_connected():
                final_state = self.aerospike_service.get_investigation(investigation_id)

            completed_at = datetime.now().isoformat()

            if final_state:
                yield {
                    "event": "state_update",
                    "data": {k: v for k, v in final_state.items() if k != "trace_events"},
                }

                # Emit metrics if available
                if "metrics" in final_state:
                    yield {
                        "event": "metrics",
                        "data": {
                            "investigation_id": investigation_id,
                            "data": final_state["metrics"],
                        },
                    }

                # Cache in memory
                self._investigation_results[investigation_id] = {
                    "user_id": user_id,
                    "completed_at": completed_at,
                    "state": final_state,
                }

                if self.aerospike_service and self.aerospike_service.is_connected():
                    self.aerospike_service.put_investigation(
                        investigation_id,
                        {**final_state, "completed_at": completed_at, "status": "completed"},
                    )

            yield {
                "event": "complete",
                "data": {"investigation_id": investigation_id, "user_id": user_id},
            }

            if investigation_id in self._active_investigations:
                self._active_investigations[investigation_id]["status"] = "completed"

        except Exception as e:
            logger.error(f"Investigation error: {e}")
            yield {
                "event": "investigation_error",
                "data": {"error": str(e), "investigation_id": investigation_id},
            }
            if investigation_id in self._active_investigations:
                self._active_investigations[investigation_id]["status"] = "error"
                self._active_investigations[investigation_id]["error"] = str(e)

    def get_investigation_status(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        return self._active_investigations.get(investigation_id)

    def get_investigation_result(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        if investigation_id in self._investigation_results:
            return self._investigation_results[investigation_id]
        if self.aerospike_service and self.aerospike_service.is_connected():
            kv_result = self.aerospike_service.get_investigation(investigation_id)
            if kv_result:
                self._investigation_results[investigation_id] = {
                    "user_id": kv_result.get("user_id"),
                    "completed_at": kv_result.get("completed_at"),
                    "state": kv_result,
                }
                return self._investigation_results[investigation_id]
        return None

    def get_user_latest_investigation(self, user_id: str) -> Optional[Dict[str, Any]]:
        if self.aerospike_service and self.aerospike_service.is_connected():
            return self.aerospike_service.get_user_latest_investigation(user_id)
        user_investigations = [
            {"investigation_id": inv_id, **data}
            for inv_id, data in self._investigation_results.items()
            if data.get("user_id") == user_id
        ]
        if not user_investigations:
            return None
        user_investigations.sort(key=lambda x: x.get("completed_at", ""), reverse=True)
        return user_investigations[0]

    def get_user_investigation_history(self, user_id: str) -> list[Dict[str, Any]]:
        if self.aerospike_service and self.aerospike_service.is_connected():
            return self.aerospike_service.get_user_investigation_history(user_id)
        history = []
        for inv_id, data in self._investigation_results.items():
            if data.get("user_id") == user_id:
                history.append({
                    "investigation_id": inv_id,
                    "completed_at": data.get("completed_at"),
                    "risk_level": data.get("state", {}).get("final_assessment", {}).get("risk_level"),
                    "recommendation": data.get("state", {}).get("final_assessment", {}).get("decision"),
                })
        return sorted(history, key=lambda x: x.get("completed_at", ""), reverse=True)

    async def get_investigation_report(self, investigation_id: str) -> Optional[str]:
        result = self._investigation_results.get(investigation_id)
        if result:
            return result.get("state", {}).get("report_markdown")
        return None


# Singleton instance (to be initialized in main.py)
investigation_service: Optional[InvestigationService] = None
