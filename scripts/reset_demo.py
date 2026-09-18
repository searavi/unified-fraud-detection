#!/usr/bin/env python3
"""
Reset the local demo environment to the exact state needed before running
the "Flagged Users -> AI Investigation -> HITL unblock" demo:

  1. Register 0 workflows in Web
  2. Registered agents visible in Web, backed by fresh Mongo data
  3. Investigation hits a real HITL block ("Enable Workflow Execution" fires)
  4. Clicking it resolves the block and the workflow runs to completion

What this script does, mirroring exactly what was done by hand once to
figure this out (see project_ufd_mongo_migration.md memory for the story):

  1. Deletes only THIS demo's accumulated workflow manifests from Mesh's run
     store (mesh-operational-store.agent-runs, docs with _id ending
     "_manifest" whose stored AgentManifest carries
     metadata.source == DEMO_SOURCE_TAG). Web's Workflows tab
     (GET /api/admin/workflows) has no filtering at all — it lists every
     manifest ever created, globally — so without this step the demo's
     "look, a new workflow appeared" moment is buried in old ones. This Mesh
     deployment may be shared with other demos, so anything NOT carrying our
     tag is left alone, never swept up by a blanket delete.
  2. Removes only this demo's entries from Mesh's HITL policy for the given
     tenant (default "default") — the specific workflow IDs step 1 just
     deleted, plus this demo's fixed agent IDs — via GET, remove, PUT. Never
     a blanket overwrite: OpaBundleController only ever bundles ONE tenant's
     policy document to OPA for the whole deployment, so if another demo is
     running in parallel and has its own entries in the same document, a
     blanket PUT would blow theirs away, not just reset ours. Never touches
     permissive_mode/executor_*/approver_* — those are shared, environment-
     wide settings this demo doesn't own. No file write, no container
     restart: Mesh and OPA share a network namespace locally, and OPA polls
     Mesh's internal/hitl/opa-bundle endpoint every 1-2s, so the PUT lands
     within seconds.
  3. Re-seeds the fraud_detection_demo Mongo database from scratch
     (delegates to seed_mongo.py --clear).
  4. Rebuilds the synktron-agent-service container from the current Agent
     repo worktree code and swaps it in, so the demo runs whatever agent
     code you're actually iterating on (not a stale container).
  5. Rebuilds and swaps the fraud-mongo-backend and fraud-mongo-frontend
     containers from the current fraud-detection worktree code.
  6. The backend registers a workflow with Mesh the instant it starts
     (see step 5) — so it's cleared again here, then both containers are
     stopped. This leaves the demo at its actual starting point: agents
     registered, zero workflows. Starting the containers live
     (`docker start fraud-mongo-backend fraud-mongo-frontend`) is itself
     step 2 of the demo — the workflow appearing is the first thing the
     audience sees happen.

Requires: docker, pymongo. Does NOT touch Web (rarely needs redeploying
between demos) or the Gemini API key's contents — that file's path is
passed straight to `docker run --env-file`, never opened or printed.

Usage:
  python scripts/reset_demo.py
  python scripts/reset_demo.py --skip-agent-rebuild   # faster, if agent code hasn't changed
  python scripts/reset_demo.py --users 40 --fraud-users 10
"""

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

try:
    from pymongo import MongoClient
except ImportError:
    print("pymongo is required: pip install pymongo>=4.6.0", file=sys.stderr)
    raise

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_AGENT_REPO = Path.home() / "Repos" / "Agent-mongo-fraud-agents"
DEFAULT_ENV_FILE = Path.home() / "Repos" / "unified-fraud-detection" / ".env"

AGENT_CONTAINER_NAME = "synktron-agent-service"
AGENT_IMAGE_TAG = "synktron-agent-service:mongo"
AGENT_NETWORK = "asgraph_net"
AGENT_NETWORK_ALIAS = "synktron-aerospike-agents"
AGENT_HOST_PORT = 8000
AGENT_CONTAINER_PORT = 8090

BACKEND_CONTAINER_NAME = "fraud-mongo-backend"
BACKEND_IMAGE_TAG = "fraud-mongo-backend:latest"
FRONTEND_CONTAINER_NAME = "fraud-mongo-frontend"
FRONTEND_IMAGE_TAG = "fraud-mongo-frontend:latest"

DEMO_BACKEND_PORT = 4010
DEMO_FRONTEND_PORT = 3734

# Must match investigation_service.py's DEMO_SOURCE_TAG and WORKFLOW_MANIFEST's task agentIds —
# two separate processes, kept in sync by convention, not by a shared import.
DEMO_SOURCE_TAG = "fraud-detection-demo"
DEMO_AGENT_IDS = ["alert_validation", "data_collection", "llm_agent", "report_generation"]


def _mesh_token(mesh_base_url: str) -> str:
    with urllib.request.urlopen(
        f"{mesh_base_url}/api/v1/mesh/security/local/token", timeout=10
    ) as resp:
        return json.loads(resp.read())["token"]


def _mesh_get_policy(mesh_base_url: str, tenant_id: str, token: str) -> "dict | None":
    """Returns the tenant's current HITL policy document, or None if none exists yet
    (Mesh returns 404 for an unconfigured tenant) — distinct from an empty document,
    since there's nothing for a remove-step to do in that case.
    """
    request = urllib.request.Request(
        f"{mesh_base_url}/api/v1/hitl/policies/{tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _mesh_put_policy(mesh_base_url: str, tenant_id: str, token: str, policy: dict) -> None:
    request = urllib.request.Request(
        f"{mesh_base_url}/api/v1/hitl/policies/{tenant_id}",
        data=json.dumps(policy).encode("utf-8"),
        method="PUT",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as resp:
        if resp.status not in (200, 204):
            raise RuntimeError(f"Mesh rejected policy update: HTTP {resp.status}")


def _remove_scoped_entries(current: dict, workflow_ids: list, agent_ids: list) -> dict:
    """Removes exactly the given workflow/agent IDs from an EXISTING policy document,
    touching nothing else — never a blanket reset. See module docstring point 2.
    """
    removed = dict(current)
    removed["workflow_policies"] = [w for w in current.get("workflow_policies", []) if w not in workflow_ids]
    removed["agent_policies"] = [a for a in current.get("agent_policies", []) if a not in agent_ids]
    removed["workflow_approvals"] = {
        k: v for k, v in current.get("workflow_approvals", {}).items() if k not in workflow_ids
    }
    removed["agent_approvals"] = {
        k: v for k, v in current.get("agent_approvals", {}).items() if k not in agent_ids
    }
    return removed


def run(cmd, **kwargs):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


def step_clear_workflow_manifests(
    mongo_uri: str, header: str = "\n=== 1. Clearing this demo's accumulated workflow manifests ==="
) -> list:
    """Deletes only the workflow manifests THIS demo created (tagged
    metadata.source == DEMO_SOURCE_TAG in the stored AgentManifest) — this store may hold
    other demos' workflows too, sharing the same Mesh deployment.

    Returns the list of workflow IDs deleted, so the caller can scrub exactly those out of
    the HITL policy document too (step_reset_opa).
    """
    print(header)
    client = MongoClient(mongo_uri)
    collection = client["mesh-operational-store"]["agent-runs"]

    # The stored run doc uses lowercase Mongo field names (response, not Response — a BSON
    # camelCase convention distinct from the JSON *inside* that field), and that inner JSON blob
    # is raw System.Text.Json default serialization of the C# AgentManifest — PascalCase member
    # names (Metadata, not metadata), unlike the camelCase GET /api/admin/workflows re-serializes
    # to on the way out. Confirmed by direct inspection of a live document, not assumed.
    candidates = list(collection.find({"_id": {"$regex": "_manifest$"}}, {"_id": 1, "response": 1}))
    tagged_ids = []
    workflow_ids = []
    for doc in candidates:
        try:
            manifest = json.loads(doc.get("response") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if manifest.get("Metadata", {}).get("source") == DEMO_SOURCE_TAG:
            tagged_ids.append(doc["_id"])
            workflow_ids.append(doc["_id"][: -len("_manifest")])

    if tagged_ids:
        collection.delete_many({"_id": {"$in": tagged_ids}})
    client.close()

    other_count = len(candidates) - len(tagged_ids)
    print(f"Deleted {len(tagged_ids)} workflow manifest(s) tagged '{DEMO_SOURCE_TAG}'.")
    if other_count:
        print(f"Left {other_count} untagged manifest(s) alone (belong to other demos sharing this Mesh).")
    return workflow_ids


def step_reset_opa(
    mesh_base_url: str,
    tenant_id: str,
    workflow_ids: list,
    header: str = "\n=== 2. Removing this demo's entries from the HITL policy ===",
) -> None:
    print(header)
    try:
        token = _mesh_token(mesh_base_url)
        current = _mesh_get_policy(mesh_base_url, tenant_id, token)
        if current is None:
            print(f"No policy document exists yet for tenant '{tenant_id}' — nothing to remove.")
            return
        removed = _remove_scoped_entries(current, workflow_ids, DEMO_AGENT_IDS)
        _mesh_put_policy(mesh_base_url, tenant_id, token, removed)
    except (urllib.error.URLError, RuntimeError) as e:
        print(f"WARNING: Failed to update HITL policy via Mesh ({mesh_base_url}) — skipping: {e}")
        return
    print(
        f"Removed {len(workflow_ids)} workflow ID(s) and {len(DEMO_AGENT_IDS)} agent ID(s) "
        f"from tenant '{tenant_id}''s policy — everything else in the document left untouched."
    )


def step_reseed_mongo(mongo_uri: str, db_name: str, users: int, fraud_users: int) -> None:
    print("\n=== 3. Re-seeding demo data ===")
    run([
        sys.executable, str(SCRIPT_DIR / "seed_mongo.py"),
        "--mongo-uri", mongo_uri,
        "--db-name", db_name,
        "--users", str(users),
        "--fraud-users", str(fraud_users),
        "--clear",
    ])


def step_rebuild_agent_container(agent_repo: Path, env_file: Path, mongo_uri: str, db_name: str) -> None:
    print("\n=== 4. Rebuilding and swapping the agent container ===")
    dockerfile = agent_repo / "src" / "Synktron.AgentFramework.Python.Service" / "Dockerfile"
    if not dockerfile.exists():
        raise FileNotFoundError(f"Dockerfile not found at {dockerfile}")

    build_context = agent_repo.parent
    repo_dir_name = agent_repo.name

    dockerfile_to_use = dockerfile
    if repo_dir_name != "Agent":
        # The Dockerfile hardcodes "Agent/src/..." COPY paths, assuming the repo
        # is checked out as a directory literally named "Agent". Rewrite that
        # prefix to match this worktree's actual name so the build works
        # regardless of directory name, without touching the real Dockerfile.
        print(f"Checkout directory is '{repo_dir_name}', not 'Agent' — adjusting COPY paths for this build")
        original = dockerfile.read_text()
        adjusted = original.replace("Agent/src/", f"{repo_dir_name}/src/")
        tmp_dockerfile = Path(tempfile.mkstemp(suffix=".Dockerfile")[1])
        tmp_dockerfile.write_text(adjusted)
        dockerfile_to_use = tmp_dockerfile

    try:
        run(["docker", "build", "-f", str(dockerfile_to_use), "-t", AGENT_IMAGE_TAG, str(build_context)])
    finally:
        if dockerfile_to_use != dockerfile:
            dockerfile_to_use.unlink(missing_ok=True)

    subprocess.run(["docker", "rm", "-f", AGENT_CONTAINER_NAME], capture_output=True)

    run_cmd = [
        "docker", "run", "-d", "--name", AGENT_CONTAINER_NAME,
        "--network", AGENT_NETWORK,
        "--network-alias", AGENT_NETWORK_ALIAS,
        "--add-host=host.docker.internal:host-gateway",
    ]
    if env_file.exists():
        # Never opened or printed — the file's contents (GEMINI_API_KEY,
        # GEMINI_MODEL, etc.) go straight from disk into the container via
        # Docker's own --env-file handling.
        run_cmd += ["--env-file", str(env_file)]
    else:
        print(f"WARNING: env file not found at {env_file} — LLM credentials won't be set.")
    run_cmd += [
        "-e", f"ConnectionStrings__MongoDB=mongodb://host.docker.internal:27017",
        "-e", f"MONGODB_DATABASE={db_name}",
        "-e", "LLM_PROVIDER=gemini",
        "-p", f"{AGENT_HOST_PORT}:{AGENT_CONTAINER_PORT}",
        AGENT_IMAGE_TAG,
        "uvicorn", "Synktron.AgentFramework.Python.Service.main:app",
        "--host", "0.0.0.0", "--port", str(AGENT_CONTAINER_PORT),
    ]
    run(run_cmd)


def step_rebuild_backend_frontend(repo: Path, mongo_uri: str, db_name: str) -> None:
    print("\n=== 5. Rebuilding and swapping the backend + frontend containers ===")
    mongo_host_uri = mongo_uri.replace("localhost", "host.docker.internal")

    run(["docker", "build", "-f", "backend.Dockerfile", "-t", BACKEND_IMAGE_TAG, "."], cwd=str(repo))
    subprocess.run(["docker", "rm", "-f", BACKEND_CONTAINER_NAME], capture_output=True)
    run([
        "docker", "run", "-d", "--name", BACKEND_CONTAINER_NAME,
        "--network", AGENT_NETWORK,
        "--add-host=host.docker.internal:host-gateway",
        "-e", f"MONGODB_CONNECTION_STRING={mongo_host_uri}",
        "-e", f"MONGODB_DATABASE={db_name}",
        "-e", "MESH_BASE_URL=http://host.docker.internal:8080",
        "-p", f"{DEMO_BACKEND_PORT}:4000",
        BACKEND_IMAGE_TAG,
    ])

    run(["docker", "build", "-f", "frontend.Dockerfile", "-t", FRONTEND_IMAGE_TAG, "."], cwd=str(repo))
    subprocess.run(["docker", "rm", "-f", FRONTEND_CONTAINER_NAME], capture_output=True)
    run([
        "docker", "run", "-d", "--name", FRONTEND_CONTAINER_NAME,
        "--network", AGENT_NETWORK,
        "-e", f"BACKEND_URL=http://{BACKEND_CONTAINER_NAME}:4000",
        "-e", f"NEXT_PUBLIC_BACKEND_URL=http://localhost:{DEMO_BACKEND_PORT}",
        "-p", f"{DEMO_FRONTEND_PORT}:8080",
        FRONTEND_IMAGE_TAG,
    ])


def step_stop_backend_frontend(mongo_uri: str, mesh_base_url: str, tenant_id: str) -> None:
    """Starting the backend (step 5) registers a workflow with Mesh immediately — clear it
    again (and scrub its HITL policy entries, in case it was ever enabled before) and stop
    both containers, so the reset leaves the demo at its real starting point (agents
    registered, zero workflows) rather than already past its own step 2.
    """
    workflow_ids = step_clear_workflow_manifests(
        mongo_uri,
        header="\n=== 6. Clearing the workflow the backend just registered, then stopping backend + frontend "
               "(workflow creation is step 2 of the demo, done live) ===",
    )
    step_reset_opa(
        mesh_base_url, tenant_id, workflow_ids,
        header="\n=== 6b. Removing the just-registered workflow's HITL policy entries (if any) ===",
    )
    run(["docker", "stop", BACKEND_CONTAINER_NAME, FRONTEND_CONTAINER_NAME])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017")
    parser.add_argument("--db-name", default="fraud_detection_demo")
    parser.add_argument("--users", type=int, default=60)
    parser.add_argument("--fraud-users", type=int, default=15)
    parser.add_argument("--mesh-base-url", default="http://localhost:8080",
                         help="Mesh base URL this script (running on the host) calls to reset the HITL policy")
    parser.add_argument("--hitl-tenant-id", default="default")
    parser.add_argument("--agent-repo", type=Path, default=DEFAULT_AGENT_REPO)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE,
                         help="File with GEMINI_API_KEY/GEMINI_MODEL, passed to docker --env-file (never read by this script)")
    parser.add_argument("--skip-agent-rebuild", action="store_true",
                         help="Skip rebuilding the agent container (faster, if its code hasn't changed)")
    args = parser.parse_args()

    stale_workflow_ids = step_clear_workflow_manifests(args.mongo_uri)
    step_reset_opa(args.mesh_base_url, args.hitl_tenant_id, stale_workflow_ids)
    step_reseed_mongo(args.mongo_uri, args.db_name, args.users, args.fraud_users)
    if not args.skip_agent_rebuild:
        step_rebuild_agent_container(args.agent_repo, args.env_file, args.mongo_uri, args.db_name)
    else:
        print("\n=== 4. Skipping agent container rebuild ===")
    step_rebuild_backend_frontend(SCRIPT_DIR.parent, args.mongo_uri, args.db_name)
    step_stop_backend_frontend(args.mongo_uri, args.mesh_base_url, args.hitl_tenant_id)

    print("\n✅ Demo environment reset — at the actual starting point: agents registered, zero workflows.")
    print("   Web:      http://localhost:5000 (Agents tab populated, Workflows tab empty)")
    print(f"   Step 2 of the demo: docker start {BACKEND_CONTAINER_NAME} {FRONTEND_CONTAINER_NAME}")
    print(f"   Frontend then needs ~30-60s to finish its build before http://localhost:{DEMO_FRONTEND_PORT} answers.")


if __name__ == "__main__":
    main()
