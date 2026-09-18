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

# Tags every workflow this service registers so a reset/teardown script can find and remove
# exactly these entries out of Mesh's shared operational store and HITL policy document —
# never a blanket delete/overwrite, since other demos share the same Mesh deployment and tenant.
DEMO_SOURCE_TAG = "fraud-detection-demo"

WORKFLOW_MANIFEST = {
    "manifest": {
        "metadata": {"source": DEMO_SOURCE_TAG},
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

# Mesh and OPA share a network namespace (test-container-locally.ps1): OPA polls Mesh's
# internal/hitl/opa-bundle endpoint every 1-2s and serves whatever's in Mesh's own IPolicyStore
# for this tenant. PUT /api/v1/hitl/policies/{tenantId} is therefore a real, near-instant policy
# update — no file write, no container restart.
HITL_TENANT_ID = os.environ.get("HITL_TENANT_ID", "default")
# Comfortably above OPA's max_delay_seconds=2 polling interval.
POLICY_PROPAGATION_WAIT_SECONDS = 3

# Roles carried by the /local/token admin token (TokenService.CreateMeshTokenAsync adds both
# when MeshUser.IsAdmin is true) — authz.rego's Gate 3 (execute_workflow) checks
# input.context.roles against this list regardless of which workflow is being executed, so this
# is who may execute, not which workflow. "Which workflow" and "which agents" are scoped
# separately below via workflow_policies/agent_policies.
EXECUTOR_ROLES = ["admin", "mesh.admin"]


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

    async def _mesh_auth_header(self, mesh_token: Optional[str] = None) -> Dict[str, str]:
        """Builds the Authorization header for a Mesh call.

        When a real logged-in user's token is available (mesh_token, from the browser's
        session — see main.py's /auth/callback), it's used as-is: Mesh validates it directly,
        no Mesh-side exchange, matching Web's own proxyMeshAdminRequest pattern. Otherwise falls
        back to minting a local-dev token: Mesh's workflow endpoints require JWT claims
        (ExtractHitlContextFromClaims) — an unauthenticated call gets a 401. The /local/token
        endpoint is [AllowAnonymous] and non-production only, matching local Docker setups —
        this fallback path is unreachable once a real IdP is configured (see auth_service.py)
        and the caller has actually logged in.
        """
        if mesh_token:
            return {"Authorization": f"Bearer {mesh_token}"}

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

    # HITL policy defaults matching PolicyData's own fail-closed defaults (Mesh returns 404 for
    # a tenant with no document yet — GET_DEFAULT_POLICY is what "nothing configured" means).
    _DEFAULT_POLICY: Dict[str, Any] = {
        "permissive_mode": False,
        "workflow_policies": [],
        "agent_policies": [],
        "executor_groups": [],
        "executor_roles": [],
        "approver_groups": [],
        "approver_roles": [],
        "workflow_approvals": {},
        "agent_approvals": {},
    }

    async def _mesh_get_policy(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Fetches the tenant's current HITL policy document, or the fail-closed defaults if
        none exists yet (Mesh returns 404 for an unconfigured tenant).
        """
        response = await self._mesh_client.get(
            f"{self._mesh_base_url}/api/v1/hitl/policies/{HITL_TENANT_ID}",
            headers=headers,
        )
        if response.status_code == 404:
            return dict(self._DEFAULT_POLICY)
        response.raise_for_status()
        return response.json()

    def _merge_allow_into(self, current: Dict[str, Any]) -> Dict[str, Any]:
        """Merges this workflow's + its agents' allow/approval entries into an EXISTING policy
        document, touching nothing else. This Mesh deployment may be shared by other demos
        running their own workflows/agents in parallel — OpaBundleController only ever bundles
        ONE tenant's document to OPA, so a blanket overwrite (or a blanket permissive_mode) would
        blow away or blanket-allow everyone else's concurrently-configured policy, not just leave
        it alone. Never touches permissive_mode/executor_*/approver_* — those are shared,
        environment-wide settings, not this demo's to set (EXECUTOR_ROLES is only ever
        union-added, never removed, so an already-present role from another demo/operator is
        preserved). See authz.rego:
          - Gates 1/2 (workflow_policies/agent_policies): exact-id allowlists, union-added here.
          - Gate 3 (execute_workflow, gated on EXECUTOR_ROLES): who may execute, orthogonal to
            which workflow.
          - Gate 4 (workflow_approved) and the Agent Execution/Policy Gates (agent_approved,
            step_execute_agent): a SEPARATE approval layer, deliberately distinct from Gates 1-3
            (policy configuration vs. explicit sign-off on this specific run) — checked via
            data.workflow_approvals/data.agent_approvals regardless of Gates 1-3 passing, so both
            must be populated too, or the workflow pauses on "not explicitly approved for
            execution" even with the right policy configured.
        """
        agent_ids = [task["agentId"] for task in WORKFLOW_MANIFEST["manifest"]["tasks"]]

        workflow_policies = list(current.get("workflow_policies", []))
        if self._mesh_workflow_id not in workflow_policies:
            workflow_policies.append(self._mesh_workflow_id)

        agent_policies = list(current.get("agent_policies", []))
        for agent_id in agent_ids:
            if agent_id not in agent_policies:
                agent_policies.append(agent_id)

        executor_roles = list(current.get("executor_roles", []))
        for role in EXECUTOR_ROLES:
            if role not in executor_roles:
                executor_roles.append(role)

        workflow_approvals = dict(current.get("workflow_approvals", {}))
        workflow_approvals[self._mesh_workflow_id] = {"approved": True}

        agent_approvals = dict(current.get("agent_approvals", {}))
        for agent_id in agent_ids:
            agent_approvals[agent_id] = {"approved": True}

        merged = dict(current)
        merged["workflow_policies"] = workflow_policies
        merged["agent_policies"] = agent_policies
        merged["executor_roles"] = executor_roles
        merged["workflow_approvals"] = workflow_approvals
        merged["agent_approvals"] = agent_approvals
        return merged

    async def enable_workflow_policy_and_wait(self, mesh_token: Optional[str] = None) -> Dict[str, Any]:
        """GET the tenant's current HITL policy, merge in an allow for exactly this workflow and
        its own agents, PUT the merged document back, and wait for OPA's next bundle poll to pick
        it up. No file write, no container restart — Mesh and OPA share a network namespace and
        OPA polls Mesh's internal/hitl/opa-bundle endpoint every 1-2s.

        mesh_token: the logged-in caller's real token (see main.py's session handling), used
        as-is if provided; falls back to the local-dev /local/token shortcut otherwise.

        Returns {"success": bool, "verified": bool, "message": str}.
        """
        if not self._mesh_workflow_id:
            await self.initialize()

        try:
            headers = await self._mesh_auth_header(mesh_token)
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch Mesh admin token: {e}")
            return {"success": False, "verified": False, "message": f"Failed to authenticate to Mesh: {e}"}

        try:
            current = await self._mesh_get_policy(headers)
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch current Mesh policy: {e}")
            return {"success": False, "verified": False, "message": f"Failed to fetch current Mesh policy: {e}"}

        merged = self._merge_allow_into(current)
        try:
            response = await self._mesh_client.put(
                f"{self._mesh_base_url}/api/v1/hitl/policies/{HITL_TENANT_ID}",
                json=merged,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"Mesh rejected policy update: {e.response.status_code} {e.response.text}")
            return {
                "success": False,
                "verified": False,
                "message": f"Mesh rejected policy update ({e.response.status_code}): {e.response.text}",
            }
        except httpx.HTTPError as e:
            logger.error(f"Failed to reach Mesh policy API: {e}")
            return {"success": False, "verified": False, "message": f"Failed to reach Mesh: {e}"}

        logger.info(
            f"Policy for tenant '{HITL_TENANT_ID}' merged to allow workflow '{self._mesh_workflow_id}' "
            f"and its agents — waiting {POLICY_PROPAGATION_WAIT_SECONDS}s for OPA's next bundle poll"
        )
        await asyncio.sleep(POLICY_PROPAGATION_WAIT_SECONDS)

        agent_ids = [task["agentId"] for task in WORKFLOW_MANIFEST["manifest"]["tasks"]]
        try:
            fetched = await self._mesh_get_policy(headers)
            fetched_workflow_approvals = fetched.get("workflow_approvals", {})
            fetched_agent_approvals = fetched.get("agent_approvals", {})
            verified = (
                self._mesh_workflow_id in fetched.get("workflow_policies", [])
                and set(agent_ids) <= set(fetched.get("agent_policies", []))
                and set(EXECUTOR_ROLES) & set(fetched.get("executor_roles", []))
                and fetched_workflow_approvals.get(self._mesh_workflow_id, {}).get("approved") is True
                and all(
                    fetched_agent_approvals.get(agent_id, {}).get("approved") is True
                    for agent_id in agent_ids
                )
            )
        except httpx.HTTPError as e:
            logger.error(f"Failed to verify policy update: {e}")
            return {
                "success": True,
                "verified": False,
                "message": f"Policy PUT succeeded but could not verify it stuck: {e}",
            }

        if verified:
            return {
                "success": True,
                "verified": True,
                "message": f"Workflow '{self._mesh_workflow_id}' and its agents are now allowed to execute.",
            }
        return {
            "success": True,
            "verified": False,
            "message": "Policy PUT succeeded but Mesh does not report the expected scoped policy on read-back.",
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
        mesh_token: Optional[str] = None,
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
            mesh_headers = await self._mesh_auth_header(mesh_token)
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
