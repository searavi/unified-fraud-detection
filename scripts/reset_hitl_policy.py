#!/usr/bin/env python3
"""
Clears THIS demo's tagged workflow manifests out of Mesh's operational store and scrubs the
matching entries out of Mesh's HITL policy document for the given tenant — never a blanket
delete or a blanket policy overwrite, since the target Mesh deployment may be shared with other
demos running their own workflows/agents in parallel at the same time.

Used identically by deploy-fraud-detection-to-azure.ps1 (pre-seed reset, so a fresh deploy
reproduces the HITL block) and teardown-fraud-detection-azure.ps1 (final cleanup before the
demo's own database is dropped).

Mirrors reset_demo.py's step_clear_workflow_manifests + step_reset_opa exactly (see that
script's module docstring for the full rationale) — duplicated here as a standalone,
PowerShell-callable CLI rather than shared via import, matching this repo's existing convention
of small, independent scripts.

Usage:
  python3 reset_hitl_policy.py --mesh-base-url https://... --mesh-mongo-uri mongodb://...
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

from pymongo import MongoClient

# Must match investigation_service.py's DEMO_SOURCE_TAG and WORKFLOW_MANIFEST's task agentIds.
DEMO_SOURCE_TAG = "fraud-detection-demo"
DEMO_AGENT_IDS = ["alert_validation", "data_collection", "llm_agent", "report_generation"]


def _mesh_token(mesh_base_url: str) -> str:
    with urllib.request.urlopen(f"{mesh_base_url}/api/v1/mesh/security/local/token", timeout=10) as resp:
        return json.loads(resp.read())["token"]


def _mesh_get_policy(mesh_base_url: str, tenant_id: str, token: str):
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


def clear_tagged_workflow_manifests(mongo_uri: str) -> list:
    """Deletes only the workflow manifests tagged metadata.Source == DEMO_SOURCE_TAG from Mesh's
    operational store. Returns the deleted workflow IDs. See module docstring for why this is
    tag-scoped rather than a blanket delete.
    """
    client = MongoClient(mongo_uri)
    collection = client["mesh-operational-store"]["agent-runs"]

    # Mongo field name is lowercase "response" (a BSON camelCase convention distinct from the
    # JSON *inside* that field), and that inner JSON is raw System.Text.Json default
    # serialization of the C# AgentManifest — PascalCase member names ("Metadata", not
    # "metadata") — confirmed by direct inspection of a live document, not assumed.
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


def scrub_hitl_policy(mesh_base_url: str, tenant_id: str, workflow_ids: list) -> None:
    token = _mesh_token(mesh_base_url)
    current = _mesh_get_policy(mesh_base_url, tenant_id, token)
    if current is None:
        print(f"No policy document exists yet for tenant '{tenant_id}' — nothing to remove.")
        return
    removed = _remove_scoped_entries(current, workflow_ids, DEMO_AGENT_IDS)
    _mesh_put_policy(mesh_base_url, tenant_id, token, removed)
    print(
        f"Removed {len(workflow_ids)} workflow ID(s) and {len(DEMO_AGENT_IDS)} agent ID(s) "
        f"from tenant '{tenant_id}''s policy — everything else in the document left untouched."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mesh-base-url", required=True)
    parser.add_argument("--mesh-mongo-uri", required=True, help="Connection string for the shared Mongo instance Mesh's operational store uses.")
    parser.add_argument("--tenant-id", default="default")
    args = parser.parse_args()

    workflow_ids = clear_tagged_workflow_manifests(args.mesh_mongo_uri)
    try:
        scrub_hitl_policy(args.mesh_base_url, args.tenant_id, workflow_ids)
    except (urllib.error.URLError, RuntimeError) as e:
        print(f"WARNING: Failed to update HITL policy via Mesh ({args.mesh_base_url}): {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
