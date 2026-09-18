import os
import secrets

from fastapi import FastAPI, HTTPException, Query, Path, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from typing import Optional, List
from datetime import datetime
import json

from sse_starlette.sse import EventSourceResponse

from services.graph_service import GraphService
from services.flagged_account_service import FlaggedAccountService
from services.mongo_service import mongo_service
from services.investigation_service import InvestigationService
from services.auth_service import auth_service

from logging_config import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger('fraud_detection.api')

# Initialize services.
#
# GraphService is instantiated but never connected: this backend has no
# graph store (see scripts/seed_mongo.py — Mongo only). FlaggedAccountService
# already has graceful-degradation for a disconnected graph_service on every
# code path this trimmed backend exercises (resolve_account's device-flagging
# step returns [] immediately when graph_service.client is None), so no
# changes were needed there.
graph_service = GraphService()
flagged_account_service = FlaggedAccountService(graph_service)
investigation_service: Optional[InvestigationService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global investigation_service

    logger.info("Starting Fraud Detection API (MongoDB / Flagged Users only)")

    if mongo_service.connect():
        logger.info("MongoDB service connected")
        flagged_account_service.set_aerospike_service(mongo_service)
    else:
        logger.warning("MongoDB service not available — flagged-account endpoints will 500")

    investigation_service = InvestigationService(
        aerospike_service=mongo_service,
        graph_service=graph_service,
    )

    try:
        await investigation_service.initialize()
        logger.info("Investigation service initialized")
    except Exception as e:
        logger.warning(f"Investigation service initialization warning: {e}")

    yield

    logger.info("Shutting down Fraud Detection API")
    if investigation_service:
        await investigation_service.close()
    mongo_service.close()


app = FastAPI(
    title="Fraud Detection API",
    description="REST API for the Flagged Users investigation workflow (MongoDB-backed)",
    version="2.0.0",
    lifespan=lifespan
)

# Session cookies (for the real-login flow below) require credentialed CORS, which the Fetch
# spec forbids combining with a wildcard origin — browsers silently refuse to expose/set cookies
# on a "*" response regardless of allow_credentials. FRONTEND_ORIGIN must name the actual
# frontend origin(s) once login is in use; defaults to the local demo's own frontend port.
_frontend_origins = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3734").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Signs the session cookie holding the logged-in user's Mesh token — SESSION_SECRET_KEY must be
# set to a real secret in any deployment where login is enabled (Entra/Cognito configured);
# an ephemeral random key is fine for local dev (no persistent session needed across restarts).
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET_KEY", secrets.token_urlsafe(32)),
    same_site="lax",
    https_only=os.environ.get("SESSION_COOKIE_HTTPS_ONLY", "false").lower() == "true",
)


# ----------------------------------------------------------------------------------------------------------
# Auth (real IdP login — Entra or Cognito, whichever this deployment is configured for)
# ----------------------------------------------------------------------------------------------------------


@app.get("/auth/login")
def auth_login(request: Request):
    """Redirects to the configured IdP's login page. 404s if no IdP is configured (local dev) —
    the frontend should hide its login button in that case rather than link here.
    """
    if not auth_service.enabled:
        raise HTTPException(status_code=404, detail="No identity provider is configured for this deployment")

    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    return RedirectResponse(auth_service.build_login_redirect(state))


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = Query(...), state: str = Query(...)):
    """OAuth2 authorization-code callback. Validates state (CSRF), exchanges the code for a
    token, and stores it in the session — investigation_service.py prefers this token over
    /local/token for every subsequent Mesh call from this browser session.
    """
    expected_state = request.session.pop("oauth_state", None)
    if not expected_state or not secrets.compare_digest(expected_state, state):
        raise HTTPException(status_code=400, detail="Invalid or missing OAuth state")

    try:
        token = await auth_service.handle_callback(code)
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        raise HTTPException(status_code=502, detail=f"Login failed: {e}")

    request.session["mesh_token"] = token
    return RedirectResponse(os.environ.get("FRONTEND_URL_AFTER_LOGIN", "/"))


@app.get("/auth/status")
def auth_status(request: Request):
    """Lets the frontend show whether a real login is available and whether the current
    browser session is already logged in.
    """
    return {
        "login_available": auth_service.enabled,
        "logged_in": "mesh_token" in request.session,
    }


@app.post("/auth/logout")
def auth_logout(request: Request):
    request.session.pop("mesh_token", None)
    return {"logged_out": True}


# ----------------------------------------------------------------------------------------------------------
# Health check endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/")
def root():
    """Health check endpoint"""
    return {"message": "Fraud Detection API is running", "status": "healthy"}


@app.head("/health")
def docker_health_check():
    """Docker health check endpoint"""
    return True


@app.get("/health")
def health_check():
    """Detailed health check endpoint"""
    return {
        "status": "healthy",
        "mongo_connection": "connected" if mongo_service.is_connected() else "error",
        "timestamp": datetime.now().isoformat()
    }


# ----------------------------------------------------------------------------------------------------------
# User endpoint (account detail page)
# ----------------------------------------------------------------------------------------------------------


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Get user's profile with accounts, devices, and transactions from MongoDB"""
    try:
        user = mongo_service.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        risk_score = user.get('risk_score', 0) or 0
        if risk_score < 25:
            risk_level = "LOW"
        elif risk_score < 50:
            risk_level = "MEDIUM"
        elif risk_score < 75:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        accounts_map = user.get('accounts', {})
        devices_map = user.get('devices', {})

        accounts_list = [
            {'id': acc_id, **acc_data}
            for acc_id, acc_data in accounts_map.items()
        ] if isinstance(accounts_map, dict) else []

        devices_list = [
            {'id': dev_id, **dev_data}
            for dev_id, dev_data in devices_map.items()
        ] if isinstance(devices_map, dict) else []

        txns_list = []
        for acc in accounts_list:
            acc_id = acc.get('id', '')
            if acc_id:
                try:
                    txns = mongo_service.get_transactions_for_account(acc_id, days=7)
                    for txn in txns:
                        if txn.get('direction') != 'out':
                            continue

                        counterparty_user_id = txn.get('counterparty_user_id', '')
                        other_party_name = 'Unknown'
                        other_party_risk = 0

                        if counterparty_user_id:
                            other_user = mongo_service.get_user(counterparty_user_id)
                            if other_user:
                                other_party_name = other_user.get('name', 'Unknown')
                                other_party_risk = other_user.get('risk_score', 0) or 0

                        txns_list.append({
                            'txn': {
                                'txn_id': txn.get('txn_id', ''),
                                'amount': txn.get('amount', 0),
                                'timestamp': txn.get('timestamp', ''),
                                'type': txn.get('type', 'transfer'),
                                'fraud_score': txn.get('fraud_score', 0) or 0,
                                'status': 'flagged' if txn.get('is_fraud') else 'clean',
                            },
                            'other_party': {
                                'id': counterparty_user_id,
                                'name': other_party_name,
                                'risk_score': other_party_risk
                            }
                        })
                except Exception as e:
                    logger.warning(f"Failed to fetch transactions for account {acc_id}: {e}")

        txns_list.sort(key=lambda x: x['txn'].get('timestamp', ''), reverse=True)
        txns_list = txns_list[:50]

        return {
            "user": {
                "id": user_id,
                "name": user.get('name', ''),
                "email": user.get('email', ''),
                "phone": user.get('phone', ''),
                "age": user.get('age', 0),
                "location": user.get('location', ''),
                "occupation": user.get('occupation', ''),
                "signup_date": user.get('signup_date', ''),
                "risk_score": risk_score,
                "is_flagged": user.get('is_flagged', False),
            },
            "risk_level": risk_level,
            "accounts": accounts_list,
            "devices": devices_list,
            "txns": txns_list,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Flagged accounts (list, stats, detail, resolve)
# ----------------------------------------------------------------------------------------------------------


@app.get("/flagged-accounts")
def get_flagged_accounts_list(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Number of accounts per page"),
    status: Optional[str] = Query(None, description="Filter by status (pending_review, under_investigation, confirmed_fraud, cleared)"),
    search: Optional[str] = Query(None, description="Search by account holder name or ID")
):
    """Get paginated list of flagged accounts"""
    try:
        return flagged_account_service.get_flagged_accounts(page, page_size, status, search)
    except Exception as e:
        logger.error(f"❌ Failed to get flagged accounts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get flagged accounts: {str(e)}")


@app.get("/flagged-accounts/stats")
def get_flagged_accounts_stats():
    """Get statistics for flagged accounts"""
    try:
        return flagged_account_service.get_flagged_stats()
    except Exception as e:
        logger.error(f"❌ Failed to get flagged accounts stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@app.get("/flagged-accounts/{account_id}")
def get_flagged_account_detail(account_id: str = Path(..., description="Account ID")):
    """Get details of a specific flagged account"""
    try:
        account = flagged_account_service.get_flagged_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Flagged account not found")
        return account
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get flagged account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get flagged account: {str(e)}")


@app.post("/accounts/{account_id}/resolve")
def resolve_individual_account(
    account_id: str = Path(..., description="Account ID (e.g., A000401)"),
    resolution: str = Query(..., description="Resolution: confirmed_fraud or cleared"),
    notes: str = Query("", description="Resolution notes")
):
    """
    Resolve an individual account (account-level, not user-level).
    Updates account-fact in MongoDB with fraud=True/False. Used by the
    fraud investigation review workflow to make per-account fraud decisions
    after AI investigation.
    """
    try:
        if resolution not in ["confirmed_fraud", "cleared"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid resolution. Must be 'confirmed_fraud' or 'cleared'"
            )

        result = flagged_account_service.resolve_account(account_id, resolution, notes)

        if not result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=f"Failed to resolve account: {', '.join(result.get('errors', ['Unknown error']))}"
            )

        return {
            "message": f"Account {account_id} resolved as {resolution}",
            "result": result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to resolve account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resolve account: {str(e)}")


@app.post("/accounts/resolutions")
def get_account_resolutions(
    account_ids: List[str] = Body(..., description="List of account IDs to check")
):
    """
    Get fraud/cleared resolution status for multiple accounts.
    Used by the frontend to pre-populate decision state when loading the review page.
    """
    try:
        results = {}
        for account_id in account_ids:
            fact = mongo_service.get_account_fact(account_id)
            if fact:
                fraud_status = fact.get("fraud")
                if fraud_status is True:
                    resolution = "fraud"
                elif fraud_status is False and fact.get("cleared_date"):
                    resolution = "safe"
                else:
                    resolution = None

                results[account_id] = {
                    "resolution": resolution,
                    "fraud": fraud_status,
                    "fraud_date": fact.get("fraud_date"),
                    "fraud_reason": fact.get("fraud_reason"),
                    "cleared_date": fact.get("cleared_date"),
                    "cleared_notes": fact.get("cleared_notes")
                }
            else:
                results[account_id] = {
                    "resolution": None,
                    "fraud": None,
                    "fraud_date": None,
                    "fraud_reason": None,
                    "cleared_date": None,
                    "cleared_notes": None
                }

        return {"resolutions": results}
    except Exception as e:
        logger.error(f"❌ Failed to get account resolutions: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get account resolutions: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Investigation (AI investigation trigger + restore + HITL recovery)
# ----------------------------------------------------------------------------------------------------------


@app.post("/investigation/enable-workflow-policy")
async def enable_workflow_policy(request: Request):
    """
    Push a HITL policy to Mesh authorizing the fraud-investigation workflow and its agents to
    execute, wait for OPA's bundle poll, and verify the policy is now active. Used by the
    frontend's "Enable Workflow Execution" recovery action when Mesh blocks a run with
    errorCode "hitl_policy_missing".
    """
    if not investigation_service:
        raise HTTPException(status_code=503, detail="Investigation service not initialized")

    mesh_token = request.session.get("mesh_token")
    if auth_service.enabled and not mesh_token:
        # /local/token is Production-disabled on any deployment with a real IdP configured —
        # failing here with a clear message beats a confusing 404 from that dead-end fallback.
        raise HTTPException(status_code=401, detail="Please log in (GET /auth/login) before enabling workflow execution")
    try:
        return await investigation_service.enable_workflow_policy_and_wait(mesh_token=mesh_token)
    except Exception as e:
        logger.error(f"❌ Failed to enable workflow policy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to enable workflow policy: {str(e)}")


@app.get("/investigation/{user_id}/stream")
async def stream_investigation(
    request: Request,
    user_id: str = Path(..., description="User ID to investigate"),
    investigation_id: Optional[str] = Query(None, description="Optional existing investigation ID")
):
    """
    SSE endpoint that streams investigation progress.

    Events:
    - start: Investigation started with workflow steps
    - trace: Node execution trace events
    - progress: State updates from each node
    - complete: Investigation completed
    - investigation_error: Investigation failed (HITL block, agent failure, etc.) — named
      distinctly from the browser's native EventSource "error" event so a custom listener
      doesn't collide with connection-level error handling.
    """
    if not investigation_service:
        raise HTTPException(status_code=503, detail="Investigation service not initialized")

    mesh_token = request.session.get("mesh_token")
    not_logged_in = auth_service.enabled and not mesh_token

    def json_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    async def event_generator():
        if not_logged_in:
            # /local/token is Production-disabled on any deployment with a real IdP configured —
            # surfacing this immediately beats a confusing failure deep in the Mesh call below.
            yield {"event": "investigation_error", "data": json.dumps({"error": "Please log in (GET /auth/login) before starting an investigation"})}
            return
        try:
            async for event in investigation_service.stream_investigation(user_id, investigation_id, mesh_token=mesh_token):
                event_type = event.get("event", "message")
                event_data = event.get("data", event)
                yield {
                    "event": event_type,
                    "data": json.dumps(event_data, default=json_serializer)
                }
        except Exception as e:
            logger.error(f"Investigation stream error: {e}")
            yield {
                "event": "investigation_error",
                "data": json.dumps({"error": str(e)})
            }

    return EventSourceResponse(event_generator())


@app.get("/investigation/user/{user_id}/latest")
def get_user_latest_investigation(
    user_id: str = Path(..., description="User ID")
):
    """
    Get the most recent completed investigation for a user — used by the
    frontend to restore investigation state when navigating back to the page.
    """
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")

        latest = investigation_service.get_user_latest_investigation(user_id)

        if not latest:
            return {
                "user_id": user_id,
                "found": False,
                "investigation": None
            }

        return {
            "user_id": user_id,
            "found": True,
            "investigation": latest
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get latest investigation for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get latest investigation: {str(e)}")
