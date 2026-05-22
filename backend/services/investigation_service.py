"""
Investigation Service

Manages fraud investigations using the Synktron Mesh workflow.
Provides SSE streaming for real-time investigation progress.
"""

import asyncio
import os
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, AsyncGenerator, Optional

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
        response = await self._mesh_client.post(
            f"{self._mesh_base_url}/api/workflow/create",
            json=WORKFLOW_MANIFEST,
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
                )
            )

            # Poll for progress while Mesh runs the workflow
            emitted_steps = 0
            while not execute_task.done():
                await asyncio.sleep(2)
                try:
                    status_resp = await self._mesh_client.get(
                        f"{self._mesh_base_url}/api/workflow/status/{investigation_id}",
                        timeout=5.0,
                    )
                    if status_resp.status_code == 200:
                        completed = status_resp.json().get("completedSteps", 0)
                        while emitted_steps < completed and emitted_steps < len(STEP_NAMES):
                            yield {
                                "event": "progress",
                                "data": {
                                    "node": STEP_NAMES[emitted_steps],
                                    "phase": STEP_NAMES[emitted_steps],
                                },
                            }
                            if investigation_id in self._active_investigations:
                                self._active_investigations[investigation_id]["current_step"] = STEP_NAMES[emitted_steps]
                            emitted_steps += 1
                except Exception:
                    pass  # status poll is best-effort

            # Collect Mesh response
            mesh_resp = execute_task.result()
            mesh_resp.raise_for_status()

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
                "event": "error",
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
