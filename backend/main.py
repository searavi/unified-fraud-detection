from fastapi import FastAPI, HTTPException, Query, Path, Body, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel
import urllib.parse
import tempfile
import zipfile
import os
import shutil
import json
import subprocess
import sys

from sse_starlette.sse import EventSourceResponse

from services.fraud_service import FraudService
from services.graph_service import GraphService
from services.transaction_generator import TransactionGeneratorService
from services.performance_monitor import performance_monitor
from services.flagged_account_service import FlaggedAccountService
from services.scheduler_service import scheduler_service
from services.aerospike_service import aerospike_service
from services.investigation_service import InvestigationService
from services.feature_service import FeatureService
from services.transaction_injector import TransactionInjector
from services.progress_service import progress_service

from logging_config import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger('fraud_detection.api')

# Initialize services
graph_service = GraphService()
fraud_service = FraudService(graph_service)
transaction_generator = TransactionGeneratorService(graph_service, fraud_service, aerospike_service)
flagged_account_service = FlaggedAccountService(graph_service)
investigation_service: Optional[InvestigationService] = None
feature_service: Optional[FeatureService] = None
transaction_injector: Optional[TransactionInjector] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global investigation_service, feature_service, transaction_injector
    
    # Startup
    logger.info("Starting Fraud Detection API")
    graph_service.connect()
    
    # Connect to Aerospike KV store
    if aerospike_service.connect():
        logger.info("Aerospike KV service connected")
        # Update flagged account service to use Aerospike
        flagged_account_service.set_aerospike_service(aerospike_service)
        # Update fraud service to use Aerospike for KV transaction flagging
        fraud_service.aerospike_service = aerospike_service
        
        # Initialize feature service
        feature_service = FeatureService(aerospike_service, graph_service)
        flagged_account_service.set_feature_service(feature_service)
        logger.info("Feature service initialized")
        
        # Initialize transaction injector
        transaction_injector = TransactionInjector(graph_service, aerospike_service)
        logger.info("Transaction injector initialized")
    else:
        logger.warning("Aerospike KV service not available, using file-based storage")
    
    # Initialize investigation service
    ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.environ.get("OLLAMA_MODEL", "mistral")
    
    investigation_service = InvestigationService(
        aerospike_service=aerospike_service,
        graph_service=graph_service,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model
    )
    
    try:
        await investigation_service.initialize()
        logger.info("Investigation service initialized")
    except Exception as e:
        logger.warning(f"Investigation service initialization warning: {e}")
    
    # Setup scheduler with detection callback
    scheduler_service.set_detection_callback(flagged_account_service.run_detection)
    scheduler_service.start()
    
    # Schedule detection job based on config
    config = flagged_account_service.get_config()
    if config.get("schedule_enabled", True):
        try:
            schedule_time = config.get("schedule_time", "21:30")
            hour, minute = map(int, schedule_time.split(":"))
            scheduler_service.schedule_detection_job(hour, minute)
            logger.info(f"Detection job scheduled for {schedule_time}")
        except Exception as e:
            logger.error(f"Failed to schedule detection job: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Fraud Detection API")
    scheduler_service.shutdown()
    
    if investigation_service:
        await investigation_service.close()
    
    aerospike_service.close()
    graph_service.close()

app = FastAPI(
    title="Fraud Detection API",
    description="REST API for fraud detection using Aerospike Graph",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    graph_status = "connected" if graph_service.client else "error"
    return {
        "status": "healthy",
        "graph_connection": graph_status,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/operation-progress/{operation_id}")
def get_operation_progress(operation_id: str = Path(..., description="Operation ID to get progress for")):
    """
    Get progress for a long-running operation.
    
    Used by the frontend to poll progress during:
    - Transaction injection
    - Feature computation
    - ML detection job
    
    Returns progress percentage, current/total items, and estimated time remaining.
    """
    progress = progress_service.get_progress(operation_id)
    
    if not progress:
        return {
            "found": False,
            "operation_id": operation_id,
            "message": "Operation not found or already completed"
        }
    
    return {
        "found": True,
        **progress.to_dict()
    }


# ----------------------------------------------------------------------------------------------------------
# Dashboard endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/dashboard/stats")
def get_dashboard_stats():
    """Get dashboard statistics from KV store"""
    try:
        return aerospike_service.get_dashboard_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard stats: {str(e)}")



# ----------------------------------------------------------------------------------------------------------
# User endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/users")
def get_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Number of users per page"),
    order_by: str = Query('name', description="Field to order results by"),
    order: str = Query('asc', description="Direction to order results"),
    query: str | None = Query(None, description="Search term for user name or ID")
):
    """Get paginated list of all users from KV store"""
    try:
        return aerospike_service.get_all_users_paginated(page, page_size, order_by, order, query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get users: {str(e)}")


@app.get("/users/stats")
def get_users_stats():
    """Get user stats from KV store"""
    try:
        # Get stats by scanning users in KV
        stats = aerospike_service.get_user_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user stats: {str(e)}")


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Get user's profile with accounts, devices, and transactions from KV store"""
    try:
        user = aerospike_service.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Calculate risk level from risk score
        risk_score = user.get('risk_score', 0) or 0
        if risk_score < 25:
            risk_level = "LOW"
        elif risk_score < 50:
            risk_level = "MEDIUM"
        elif risk_score < 75:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        # Format response to match frontend expectations
        # Convert nested accounts/devices maps to arrays
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
        
        # Fetch transactions from Aerospike KV for all user's accounts
        txns_list = []
        for acc in accounts_list:
            acc_id = acc.get('id', '')
            if acc_id:
                try:
                    txns = aerospike_service.get_transactions_for_account(acc_id, days=7)
                    for txn in txns:
                        # Only include outgoing transactions to avoid duplicates
                        if txn.get('direction') != 'out':
                            continue
                        
                        # Get counterparty user info
                        counterparty_user_id = txn.get('counterparty_user_id', '')
                        other_party_name = 'Unknown'
                        other_party_risk = 0
                        
                        if counterparty_user_id:
                            other_user = aerospike_service.get_user(counterparty_user_id)
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
        
        # Sort by timestamp descending and limit
        txns_list.sort(key=lambda x: x['txn'].get('timestamp', ''), reverse=True)
        txns_list = txns_list[:50]  # Limit to 50 most recent
        
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



@app.get("/users/{user_id}/connected-devices")
def get_user_connected_devices(user_id: str = Path(..., description="User ID")):
    """Get users who share devices with the specified user"""
    try:
        connected_users = []
        
        # Use graph service to find users sharing devices
        if graph_service.client:
            try:
                raw_connected = graph_service.get_user_connected_devices(user_id)
                for conn in raw_connected:
                    connected_users.append({
                        "user_id": conn.get('user_id', ''),
                        "name": conn.get('name', 'Unknown'),
                        "risk_score": conn.get('risk_score', 0),
                        "shared_devices": [],  # Could be populated with specific device IDs
                        "shared_device_count": conn.get('shared_device_count', 0)
                    })
            except Exception as e:
                logger.warning(f"Failed to fetch connected users from graph: {e}")
        
        return {
            "user_id": user_id,
            "connected_users": connected_users,
            "total_connections": len(connected_users)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get connected device users: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Transaction endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/transactions")
def get_transactions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(12, ge=1, le=100, description="Number of transactions per page"),
    day: str | None = Query(None, description="Date filter (YYYY-MM-DD), defaults to today")
):
    """Get paginated list of transactions for today (or specified day) from KV store"""
    try:
        # Default to today's date if not specified
        if not day:
            day = datetime.now().strftime('%Y-%m-%d')
        results = aerospike_service.get_transactions_by_day(day, page, page_size)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get transactions: {str(e)}")



@app.delete("/transactions")
def delete_all_transactions():
    """Delete all transactions from the graph"""
    try:
        result = graph_service.drop_all_transactions()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to drop all transactions: {str(e)}")


@app.get("/transactions/stats")
def get_transaction_stats():
    """Get transaction stats from KV store"""
    try:
        results = aerospike_service.get_transaction_stats()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get transaction stats: {str(e)}")



@app.get("/transaction/{account_id}/{day}/{txn_id}")
def get_transaction_detail_kv(account_id: str, day: str, txn_id: str):
    """Get transaction details from KV store by account_id, day, and txn_id"""
    try:
        txn = aerospike_service.get_transaction_by_id(account_id, day, txn_id)
        if not txn:
            raise HTTPException(status_code=404, detail="Transaction not found")
        
        # Get sender and receiver user details from KV
        sender_user = aerospike_service.get_user(txn.get('user_id', '')) if txn.get('user_id') else None
        receiver_user = aerospike_service.get_user(txn.get('counterparty_user_id', '')) if txn.get('counterparty_user_id') else None
        
        # Get account details from user's accounts map
        counterparty_account_id = txn.get('counterparty', '')
        
        sender_account = {}
        if sender_user and sender_user.get('accounts'):
            sender_account = sender_user['accounts'].get(account_id, {})
        
        receiver_account = {}
        if receiver_user and receiver_user.get('accounts'):
            receiver_account = receiver_user['accounts'].get(counterparty_account_id, {})
        
        # Get fraud details from Graph DB (RT1, RT2, RT3 results)
        fraud_details = graph_service.get_fraud_details_by_txn_id(txn_id)
        
        # Build response matching frontend expectations
        return {
            "txn": {
                "txn_id": txn.get('txn_id', ''),
                "amount": txn.get('amount', 0),
                "type": txn.get('type', 'transfer'),
                "method": txn.get('method', 'electronic'),
                "location": txn.get('location', ''),
                "timestamp": txn.get('timestamp', ''),
                "status": txn.get('status', 'completed'),
                "is_fraud": txn.get('is_fraud', False),
                "fraud_score": txn.get('fraud_score', 0),
                "device_id": txn.get('device_id', ''),
                # Include fraud details from Graph for the Fraud Analysis tab
                "details": fraud_details.get('details', []) if fraud_details else [],
                "fraud_status": fraud_details.get('fraud_status', '') if fraud_details else '',
                "eval_timestamp": fraud_details.get('eval_timestamp', '') if fraud_details else '',
            },
            "src": {
                "account": {
                    "id": account_id,
                    "type": sender_account.get('type', ''),
                    "balance": sender_account.get('balance', 0),
                    "bank_name": sender_account.get('bank_name', ''),
                    "status": sender_account.get('status', 'active'),
                },
                "user": {
                    "id": txn.get('user_id', ''),
                    "name": sender_user.get('name', '') if sender_user else '',
                    "email": sender_user.get('email', '') if sender_user else '',
                    "location": sender_user.get('location', '') if sender_user else '',
                } if sender_user else None,
            },
            "dest": {
                "account": {
                    "id": counterparty_account_id,
                    "type": receiver_account.get('type', ''),
                    "balance": receiver_account.get('balance', 0),
                    "bank_name": receiver_account.get('bank_name', ''),
                    "status": receiver_account.get('status', 'active'),
                },
                "user": {
                    "id": txn.get('counterparty_user_id', ''),
                    "name": receiver_user.get('name', '') if receiver_user else '',
                    "email": receiver_user.get('email', '') if receiver_user else '',
                    "location": receiver_user.get('location', '') if receiver_user else '',
                } if receiver_user else None,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get transaction detail: {str(e)}")


@app.get("/transaction/{transaction_id}")
def get_transaction_detail_legacy(transaction_id: str):
    """Legacy: Get transaction details from Graph by txn_id (backward compatibility)"""
    try:
        transaction_detail = graph_service.get_transaction_summary(urllib.parse.unquote(transaction_id))
        if not transaction_detail:
            raise HTTPException(status_code=404, detail="Transaction not found")
        return transaction_detail
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get transaction detail: {str(e)}")
        

# ----------------------------------------------------------------------------------------------------------
# Transaction generation endpoints
# ----------------------------------------------------------------------------------------------------------




@app.post("/transaction-generation/manual")
def create_manual_transaction(
    from_account_id: str = Query(..., description="Source account ID"),
    to_account_id: str = Query(..., description="Destination account ID"), 
    amount: float = Query(..., gt=0, description="Transaction amount"),
    transaction_type: str = Query("transfer", description="Transaction type")
):
    """Create a manual transaction between specific accounts"""
    try:
        logger.info(f"Attempting to create manual transaction from {from_account_id} to {to_account_id} amount {amount}")
        result = transaction_generator.create_manual_transaction(
            from_id=from_account_id,
            to_id=to_account_id,
            amount=amount,
            type=transaction_type,
            gen_type="MANUAL"
        )
        
        if result:
            logger.info(f"✅ Transaction created")
            return {
                "message": "Transaction created successfully",
            }
        else:
            logger.error("❌ Failed to create manual transaction")
            raise HTTPException(status_code=400, detail="Failed to create transaction")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to create manual transaction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create manual transaction: {str(e)}")


@app.post("/transaction-generation/generate")
def generate_single_transaction():
    """Generate one transaction (used by Bulk Generation workers). Writes to Graph and KV so transactions appear on the Transaction page."""
    try:
        transaction_generator.generate_transaction()
        return {"status": "created"}
    except Exception as e:
        logger.warning(f"Transaction generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Max Rate Configuration Endpoints
@app.get("/transaction-generation/max-rate")
def get_max_generation_rate():
    """Get the current maximum transaction generation rate"""
    max_generation_rate = transaction_generator.get_max_transaction_rate()
    return {
        "max_rate": max_generation_rate,
        "message": f"Maximum allowed transaction generation rate: {max_generation_rate} transactions/second"
    }




# ----------------------------------------------------------------------------------------------------------
# Account endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/accounts")
def get_all_accounts():
    """Get all accounts for manual transaction dropdowns"""
    try:
        accounts = graph_service.get_all_accounts()
        return { "accounts": accounts }
    except Exception as e:
        logger.error(f"❌ Failed to get accounts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get accounts: {str(e)}")




# ----------------------------------------------------------------------------------------------------------
# Performance monitoring endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/performance/stats")
def get_performance_stats(time_window: int = Query(5, ge=1, le=60, description="Time window in minutes")):
    """Get performance statistics for all fraud detection methods"""
    try:
        stats = performance_monitor.get_all_stats(time_window)
        return {
            "performance_stats": stats,
            "time_window_minutes": time_window,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Failed to get performance stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance stats: {str(e)}")


@app.get("/performance/timeline")
def get_performance_timeline(minutes: int = Query(5, ge=1, le=60, description="Timeline window in minutes")):
    """Get timeline data for performance charts"""
    try:
        timeline_data = performance_monitor.get_recent_timeline_data(minutes)
        return {
            "timeline_data": timeline_data,
            "time_window_minutes": minutes,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Failed to get performance timeline: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance timeline: {str(e)}")


@app.post("/performance/reset")
def reset_performance_metrics():
    """Reset all performance metrics"""
    try:
        performance_monitor.reset_metrics()
        return {
            "message": "Performance metrics reset successfully",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Failed to reset performance metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset performance metrics: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Bulk loading endpoints
# ----------------------------------------------------------------------------------------------------------


ALLOWED_LOCALES = frozenset({"american", "indian", "en_GB", "en_AU", "zh_CN"})


@app.post("/bulk-load-csv")
def bulk_load_csv_data(
    vertices_path: Optional[str] = None,
    edges_path: Optional[str] = None,
    load_graph: bool = True,
    load_aerospike: bool = True,
    locale: Optional[str] = None
):
    """
    Bulk load data from CSV files.
    
    By default loads to both:
    - Aerospike Graph (vertices and edges)
    - Aerospike KV (users for risk evaluation tracking)
    
    When locale is provided and vertices_path is not set, runs the user data
    generator for the selected locale before loading.
    
    Args:
        vertices_path: Path to vertices CSV directory
        edges_path: Path to edges CSV directory
        load_graph: Load data into Aerospike Graph (default: True)
        load_aerospike: Load users into Aerospike KV for tracking (default: True)
        locale: Demographics region for default data (american, indian, en_GB, en_AU, zh_CN)
    """
    result = {
        "success": True,
        "graph": None,
        "aerospike": None,
        "message": ""
    }
    
    # Validate locale if provided
    if locale is not None and locale not in ALLOWED_LOCALES:
        raise HTTPException(status_code=400, detail=f"Invalid locale. Allowed: {sorted(ALLOWED_LOCALES)}")
    
    # Calculate total steps for progress tracking
    total_steps = 0
    run_generator = locale is not None and vertices_path is None
    if run_generator:
        total_steps += 1  # Generating locale-specific data
    if load_graph:
        total_steps += 3  # Graph: start, load, verify
    if load_aerospike:
        total_steps += 3  # KV: start, load users, complete
    total_steps = max(total_steps, 1)
    
    # Start progress tracking
    progress_service.start_operation("bulk_load", total_steps, "Initializing bulk load...")
    current_step = 0
    
    try:
        # When using default path and locale is set, run the generator script first
        if run_generator:
            current_step += 1
            progress_service.update_progress("bulk_load", current_step, "Generating locale-specific data...")
            script_path = "/backend/scripts/generate_user_data.py"
            if not os.path.exists(script_path):
                logger.error(f"Generator script not found: {script_path}")
                progress_service.fail_operation("bulk_load", "Generator script not found", "Bulk load failed")
                raise HTTPException(status_code=500, detail="Generator script not found")
            try:
                proc = subprocess.run(
                    [sys.executable, script_path, "--region", locale, "--users", "10000", "--output", "/data/graph_csv", "--seed", "42"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd="/backend"
                )
                if proc.returncode != 0:
                    logger.error(f"Generator failed: stdout={proc.stdout!r}, stderr={proc.stderr!r}")
                    progress_service.fail_operation("bulk_load", proc.stderr or proc.stdout or "Generator failed", "Bulk load failed")
                    raise HTTPException(status_code=500, detail=f"Data generation failed: {proc.stderr or proc.stdout or 'Unknown error'}")
                logger.info(f"Generator completed: {proc.stdout[:500] if proc.stdout else 'ok'}")
            except subprocess.TimeoutExpired:
                logger.error("Generator timed out after 300s")
                progress_service.fail_operation("bulk_load", "Generator timed out", "Bulk load failed")
                raise HTTPException(status_code=500, detail="Data generation timed out after 300 seconds")
        
        # Clear existing transacts.csv before bulk load to prevent loading stale transactions
        transacts_path = "/data/graph_csv/edges/transactions/transacts.csv"
        if os.path.exists(transacts_path):
            os.remove(transacts_path)
            logger.info("Cleared existing transacts.csv before bulk load")
        
        # Load to Graph DB
        if load_graph:
            current_step += 1
            progress_service.update_progress("bulk_load", current_step, "📊 Graph: Starting bulk load...")
            
            graph_result = graph_service.bulk_load_csv_data(vertices_path, edges_path)
            result["graph"] = graph_result
            
            current_step += 1
            if graph_result["success"]:
                stats = graph_result.get("statistics", {})
                progress_service.update_progress(
                    "bulk_load", current_step, 
                    f"📊 Graph: Loaded {stats.get('users', 0)} users, {stats.get('accounts', 0)} accounts, {stats.get('devices', 0)} devices"
                )
            else:
                result["success"] = False
                result["message"] = f"Graph load failed: {graph_result.get('error', 'Unknown error')}"
                progress_service.update_progress("bulk_load", current_step, f"📊 Graph: Failed - {graph_result.get('error', 'Unknown')}")
            
            current_step += 1
            progress_service.update_progress("bulk_load", current_step, "📊 Graph: Load complete")
        
        # Load users to Aerospike KV
        if load_aerospike:
            current_step += 1
            progress_service.update_progress("bulk_load", current_step, "🗄️ KV Store: Starting user load...")
            
            if aerospike_service.is_connected():
                # Determine the CSV path for users
                users_csv_path = None
                effective_vertices_path = vertices_path if vertices_path else "/data/graph_csv/vertices"
                users_csv_path = f"{effective_vertices_path}/users/users.csv"
                
                current_step += 1
                progress_service.update_progress("bulk_load", current_step, "🗄️ KV Store: Loading users, accounts, devices...")
                
                aerospike_result = aerospike_service.load_users_from_csv(users_csv_path)
                result["aerospike"] = aerospike_result
                
                current_step += 1
                if aerospike_result["success"]:
                    users = aerospike_result.get('loaded', 0)
                    accounts = aerospike_result.get('accounts_loaded', 0)
                    devices = aerospike_result.get('devices_loaded', 0)
                    progress_service.update_progress(
                        "bulk_load", current_step, 
                        f"🗄️ KV Store: Loaded {users} users, {accounts} accounts, {devices} devices"
                    )
                else:
                    # Don't fail entire operation, just note the error
                    logger.warning(f"Aerospike load warning: {aerospike_result.get('message', 'Unknown error')}")
                    progress_service.update_progress("bulk_load", current_step, f"🗄️ KV Store: Warning - {aerospike_result.get('message', '')}")
            else:
                result["aerospike"] = {
                    "success": False,
                    "message": "Aerospike KV service not available - skipped",
                    "loaded": 0
                }
                logger.warning("Aerospike KV not available, skipping user load")
        
        # Build summary message
        messages = []
        if load_graph and result["graph"]:
            if result["graph"]["success"]:
                stats = result["graph"].get("statistics", {})
                messages.append(f"Graph: {stats.get('users', 0)} users, {stats.get('accounts', 0)} accounts, {stats.get('devices', 0)} devices")
            else:
                messages.append(f"Graph: Failed")
        
        if load_aerospike and result["aerospike"]:
            if result["aerospike"]["success"]:
                users = result['aerospike'].get('loaded', 0)
                accounts = result['aerospike'].get('accounts_loaded', 0)
                devices = result['aerospike'].get('devices_loaded', 0)
                messages.append(f"Aerospike KV: {users} users, {accounts} accounts, {devices} devices")
            else:
                messages.append(f"Aerospike KV: {result['aerospike'].get('message', 'Failed')}")
        
        result["message"] = " | ".join(messages) if messages else "No operations performed"
        
        # Complete progress tracking
        progress_service.complete_operation("bulk_load", result["message"])
        
        return result
        
    except Exception as e:
        logger.error(f"Bulk load failed: {e}")
        progress_service.fail_operation("bulk_load", str(e), "Bulk load failed")
        raise HTTPException(status_code=500, detail=f"Failed to bulk load data: {str(e)}")

@app.get("/bulk-load-status")
def get_bulk_load_status():
    """Get the status of the current bulk load operation"""
    try:
        result = graph_service.get_bulk_load_status()
        
        if result["success"]:
            return result
        else:
            return {
                "message": result["message"],
                "error": result["error"],
                "status": None
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get bulk load status: {str(e)}")





class InjectBulkBody(BaseModel):
    """Optional body for inject-transactions-bulk (locale preferred from body for POST)."""
    locale: Optional[str] = None


@app.post("/inject-transactions-bulk")
def inject_transactions_bulk(
    transaction_count: int = Query(10000, ge=100, le=100000, description="Number of transactions to generate"),
    spread_days: int = Query(30, ge=1, le=365, description="Days to spread transactions over"),
    fraud_percentage: float = Query(0.15, ge=0.0, le=0.5, description="Percentage of fraudulent transactions"),
    locale: Optional[str] = None,
    body: Optional[InjectBulkBody] = Body(None)
):
    """
    Bulk inject historical transactions using optimized batch operations.
    
    This endpoint is significantly faster than /inject-transactions because:
    1. Pre-fetches all account→user mappings from KV (1 scan vs 2 Graph queries per txn)
    2. Generates all transactions in memory first
    3. Writes CSV for Graph native bulk loader (1 bulk load vs N Gremlin queries)
    4. Batch writes to KV (1 batch vs 2N individual writes)
    
    For 10,000 transactions: ~3 DB operations instead of ~50,000.
    """
    # Prefer locale from request body (reliable for POST); fall back to query
    locale = locale or (body.locale if body else None)
    logger.info(f"Inject transactions bulk: locale={locale!r} (will use regional locations/currency)")
    if locale is not None and locale not in ALLOWED_LOCALES:
        raise HTTPException(status_code=400, detail=f"Invalid locale. Allowed: {sorted(ALLOWED_LOCALES)}")
    if not transaction_injector:
        raise HTTPException(status_code=503, detail="Transaction injector not available. Aerospike may not be connected.")
    
    try:
        result = transaction_injector.inject_transactions_bulk(
            transaction_count=transaction_count,
            spread_days=spread_days,
            fraud_percentage=fraud_percentage,
            locale=locale
        )
        return result
    except Exception as e:
        logger.error(f"Bulk transaction injection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to bulk inject transactions: {str(e)}")


@app.post("/compute-features")
def compute_features(
    window_days: int = Query(7, ge=1, le=90, description="Sliding window in days")
):
    """
    Compute account and device features from transaction data.
    
    This runs the feature computation job which:
    - Reads transactions from KV transactions set
    - Computes 15 account features and 5 device features
    - Stores results in account-fact and device-fact sets
    
    Should be run before ML detection for accurate scoring.
    """
    if not feature_service:
        raise HTTPException(status_code=503, detail="Feature service not available. Aerospike may not be connected.")
    
    try:
        result = feature_service.run_feature_computation_job(window_days=window_days)
        return result
    except Exception as e:
        logger.error(f"Feature computation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to compute features: {str(e)}")


@app.delete("/delete-all-data")
def delete_all_data(confirm: bool = Query(False, description="Must be True to confirm deletion")):
    """
    Delete all data from both Graph and KV stores.
    
    This is a destructive operation that:
    - Truncates all KV sets (users, transactions, account-fact, device-fact, flagged_accounts)
    - Drops all graph vertices (which also removes edges)
    
    Use with caution!
    """
    if not confirm:
        raise HTTPException(status_code=400, detail="Must set confirm=True to delete all data")
    
    result = {
        "kv_truncated": {},
        "graph_cleared": False,
        "errors": []
    }
    
    try:
        # Truncate KV sets
        if aerospike_service.is_connected():
            result["kv_truncated"] = aerospike_service.truncate_all_data()
            logger.info(f"KV sets truncated: {result['kv_truncated']}")
        else:
            result["errors"].append("Aerospike not connected")
        
        # Clear graph
        if graph_service.client:
            try:
                graph_service.client.V().drop().iterate()
                result["graph_cleared"] = True
                logger.info("Graph vertices dropped")
            except Exception as e:
                result["errors"].append(f"Graph drop failed: {str(e)}")
        else:
            result["errors"].append("Graph not connected")
        
        return result
        
    except Exception as e:
        logger.error(f"Delete all data failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete data: {str(e)}")



@app.post("/bulk-load-upload")
async def bulk_load_upload(
    file: UploadFile = File(...),
    load_graph: bool = Form(True),
    load_aerospike: bool = Form(True)
):
    """
    Upload and bulk load data from a ZIP file.
    
    The ZIP file should contain:
    - vertices/users/users.csv
    - vertices/accounts/accounts.csv  
    - vertices/devices/devices.csv
    - edges/ownership/owns.csv
    - edges/usage/uses.csv
    
    Args:
        file: ZIP file containing CSV data
        load_graph: Load data into Aerospike Graph (default: True)
        load_aerospike: Load users into Aerospike KV for tracking (default: True)
    """
    result = {
        "success": True,
        "graph": None,
        "aerospike": None,
        "message": ""
    }
    
    temp_dir = None
    
    try:
        # Validate file type
        if not file.filename or not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="File must be a ZIP archive")
        
        # Create temporary directory in shared volume so Graph service can access files
        upload_dir = "/data/uploads"
        os.makedirs(upload_dir, exist_ok=True)
        temp_dir = tempfile.mkdtemp(prefix="bulk_load_", dir=upload_dir)
        zip_path = os.path.join(temp_dir, "upload.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        
        # Save uploaded file
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Extract ZIP file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        logger.info(f"Extracted uploaded ZIP to {extract_dir}")
        
        # Find the vertices and edges directories
        vertices_path = None
        edges_path = None
        
        for root, dirs, files in os.walk(extract_dir):
            if 'vertices' in dirs:
                vertices_path = os.path.join(root, 'vertices')
            if 'edges' in dirs:
                edges_path = os.path.join(root, 'edges')
        
        if not vertices_path or not edges_path:
            raise HTTPException(
                status_code=400, 
                detail="ZIP file must contain 'vertices' and 'edges' directories"
            )
        
        # Load to Graph DB
        if load_graph:
            graph_result = graph_service.bulk_load_csv_data(vertices_path, edges_path)
            result["graph"] = graph_result
            
            if not graph_result["success"]:
                result["success"] = False
                result["message"] = f"Graph load failed: {graph_result.get('error', 'Unknown error')}"
        
        # Load users to Aerospike KV
        if load_aerospike:
            if aerospike_service.is_connected():
                users_csv_path = os.path.join(vertices_path, "users", "users.csv")
                
                if os.path.exists(users_csv_path):
                    aerospike_result = aerospike_service.load_users_from_csv(users_csv_path)
                    result["aerospike"] = aerospike_result
                    
                else:
                    result["aerospike"] = {
                        "success": False,
                        "message": "users.csv not found in uploaded data",
                        "loaded": 0
                    }
            else:
                result["aerospike"] = {
                    "success": False,
                    "message": "Aerospike KV service not available - skipped",
                    "loaded": 0
                }
        
        # Build summary message
        messages = []
        if load_graph and result["graph"]:
            if result["graph"]["success"]:
                stats = result["graph"].get("statistics", {})
                messages.append(f"Graph: {stats.get('users', 0)} users, {stats.get('accounts', 0)} accounts, {stats.get('devices', 0)} devices")
            else:
                messages.append(f"Graph: Failed")
        
        if load_aerospike and result["aerospike"]:
            if result["aerospike"]["success"]:
                users = result['aerospike'].get('loaded', 0)
                accounts = result['aerospike'].get('accounts_loaded', 0)
                devices = result['aerospike'].get('devices_loaded', 0)
                messages.append(f"Aerospike KV: {users} users, {accounts} accounts, {devices} devices")
            else:
                messages.append(f"Aerospike KV: {result['aerospike'].get('message', 'Failed')}")
        
        result["message"] = " | ".join(messages) if messages else "No operations performed"
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk load upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded file: {str(e)}")
    finally:
        # Cleanup temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory: {e}")



@app.get("/aerospike/stats")
def get_aerospike_stats():
    """Get statistics about data stored in Aerospike"""
    try:
        if not aerospike_service.is_connected():
            return {
                "connected": False,
                "message": "Aerospike KV service not available"
            }
        
        stats = aerospike_service.get_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get Aerospike stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Flagged Accounts Detection endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/flagged-accounts")
def get_flagged_accounts_list(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Number of accounts per page"),
    status: Optional[str] = Query(None, description="Filter by status (pending_review, under_investigation, confirmed_fraud, cleared)"),
    search: Optional[str] = Query(None, description="Search by account holder name or ID")
):
    """Get paginated list of flagged accounts detected by the ML model"""
    try:
        result = flagged_account_service.get_flagged_accounts(page, page_size, status, search)
        return result
    except Exception as e:
        logger.error(f"❌ Failed to get flagged accounts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get flagged accounts: {str(e)}")


@app.get("/flagged-accounts/stats")
def get_flagged_accounts_stats():
    """Get statistics for flagged accounts"""
    try:
        stats = flagged_account_service.get_flagged_stats()
        return stats
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


@app.post("/flagged-accounts/{account_id}/resolve")
def resolve_flagged_account(
    account_id: str = Path(..., description="Account ID"),
    resolution: str = Query(..., description="Resolution: confirmed_fraud or cleared"),
    notes: str = Query("", description="Resolution notes")
):
    """Resolve a flagged account as confirmed fraud or cleared"""
    try:
        if resolution not in ["confirmed_fraud", "cleared", "under_investigation"]:
            raise HTTPException(status_code=400, detail="Invalid resolution. Must be 'confirmed_fraud', 'cleared', or 'under_investigation'")
        
        result = flagged_account_service.resolve_flagged_account(account_id, resolution, notes)
        if not result:
            raise HTTPException(status_code=404, detail="Flagged account not found")
        
        return {
            "message": f"Account {account_id} resolved as {resolution}",
            "account": result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to resolve flagged account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resolve account: {str(e)}")


@app.post("/accounts/{account_id}/resolve")
def resolve_individual_account(
    account_id: str = Path(..., description="Account ID (e.g., A000401)"),
    resolution: str = Query(..., description="Resolution: confirmed_fraud or cleared"),
    notes: str = Query("", description="Resolution notes")
):
    """
    Resolve an individual account (account-level, not user-level).
    
    When confirmed_fraud:
    - Updates account's fraud_flag in Graph DB
    - Updates account-fact in KV with fraud=True
    - Flags all devices used in this account's transactions in both Graph and KV
    
    When cleared:
    - Updates account's fraud_flag=False in Graph DB
    - Updates account-fact in KV with fraud=False
    
    This endpoint is used by the fraud investigation review workflow to make
    per-account fraud decisions after AI investigation.
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
    
    Returns the fraud status from account-fact KV store for each account.
    Used by the frontend to pre-populate decision state when loading the review page.
    """
    try:
        results = {}
        for account_id in account_ids:
            fact = aerospike_service.get_account_fact(account_id)
            if fact:
                # Determine resolution status
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


@app.post("/flagged-accounts/detect")
def trigger_detection_job(
    skip_cooldown: bool = Query(False, description="Skip cooldown period and evaluate all users")
):
    """
    Manually trigger the flagged account detection job.
    
    By default, users evaluated within the cooldown period (7 days) are skipped.
    Set skip_cooldown=true to force evaluation of ALL users regardless of when they were last evaluated.
    """
    try:
        # Check if Aerospike KV is connected - required for risk evaluation
        if not aerospike_service.is_connected():
            raise HTTPException(
                status_code=503, 
                detail="Aerospike KV service is not available. Risk evaluation requires Aerospike to be connected."
            )
        
        cooldown_msg = " (skip cooldown)" if skip_cooldown else ""
        logger.info(f"Manual detection job triggered via API{cooldown_msg}")
        result = scheduler_service.run_detection_now(skip_cooldown=skip_cooldown)
        return {
            "message": "Detection job completed",
            "skip_cooldown": skip_cooldown,
            "result": result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to run detection job: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to run detection job: {str(e)}")



# ----------------------------------------------------------------------------------------------------------
# Detection Configuration endpoints
# ----------------------------------------------------------------------------------------------------------


@app.get("/detection/config")
def get_detection_config():
    """Get current detection configuration (schedule, cooldown, threshold)"""
    try:
        config = flagged_account_service.get_config()
        scheduler_status = scheduler_service.get_status()
        
        return {
            "config": config,
            "scheduler": scheduler_status
        }
    except Exception as e:
        logger.error(f"❌ Failed to get detection config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get config: {str(e)}")


@app.post("/detection/config")
def update_detection_config(
    schedule_enabled: Optional[bool] = Body(None, description="Enable/disable scheduled detection"),
    schedule_time: Optional[str] = Body(None, description="Schedule time in HH:MM format (24-hour)"),
    cooldown_days: Optional[int] = Body(None, ge=1, description="Cooldown period in days"),
    risk_threshold: Optional[float] = Body(None, ge=0, le=100, description="Risk score threshold for flagging")
):
    """Update detection configuration"""
    try:
        # Build config update dict
        config_update = {}
        if schedule_enabled is not None:
            config_update["schedule_enabled"] = schedule_enabled
        if schedule_time is not None:
            config_update["schedule_time"] = schedule_time
        if cooldown_days is not None:
            config_update["cooldown_days"] = cooldown_days
        if risk_threshold is not None:
            config_update["risk_threshold"] = risk_threshold
        
        # Update config
        new_config = flagged_account_service.update_config(config_update)
        
        # Update scheduler if schedule changed
        if schedule_time is not None or schedule_enabled is not None:
            if new_config.get("schedule_enabled"):
                try:
                    time_str = new_config.get("schedule_time", "21:30")
                    hour, minute = map(int, time_str.split(":"))
                    scheduler_service.schedule_detection_job(hour, minute)
                    logger.info(f"Detection job rescheduled for {time_str}")
                except Exception as e:
                    logger.error(f"Failed to reschedule detection job: {e}")
            else:
                scheduler_service.remove_detection_job()
                logger.info("Detection job disabled")
        
        return {
            "message": "Configuration updated",
            "config": new_config,
            "scheduler": scheduler_service.get_status()
        }
    except Exception as e:
        logger.error(f"❌ Failed to update detection config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")


@app.get("/detection/history")
def get_detection_history(
    limit: int = Query(20, ge=1, le=100, description="Number of history records to return")
):
    """Get detection job run history"""
    try:
        history = flagged_account_service.get_detection_history(limit)
        return {
            "history": history,
            "total": len(history)
        }
    except Exception as e:
        logger.error(f"❌ Failed to get detection history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")


# ----------------------------------------------------------------------------------------------------------
# Investigation endpoints (LangGraph-powered fraud investigation)
# ----------------------------------------------------------------------------------------------------------


@app.get("/investigation/steps")
def get_investigation_steps():
    """Get list of investigation workflow steps"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        steps = investigation_service.get_workflow_steps()
        return {
            "steps": steps,
            "total": len(steps)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get investigation steps: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get steps: {str(e)}")


@app.post("/investigation/enable-workflow-policy")
async def enable_workflow_policy():
    """
    Push a HITL policy to Mesh authorizing the fraud-investigation workflow and its agents to
    execute, wait for OPA's bundle poll, and verify the policy is now active. Used by the
    frontend's "Enable Workflow Execution" recovery action when Mesh blocks a run with
    errorCode "hitl_policy_missing".
    """
    if not investigation_service:
        raise HTTPException(status_code=503, detail="Investigation service not initialized")

    try:
        result = await investigation_service.enable_workflow_policy_and_wait()
        return result
    except Exception as e:
        logger.error(f"❌ Failed to enable workflow policy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to enable workflow policy: {str(e)}")


@app.get("/investigation/{user_id}/stream")
async def stream_investigation(
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
    
    def json_serializer(obj):
        """Custom JSON serializer for objects not serializable by default json code"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
    
    async def event_generator():
        try:
            async for event in investigation_service.stream_investigation(user_id, investigation_id):
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


@app.post("/investigation/{user_id}/start")
async def start_investigation(
    user_id: str = Path(..., description="User ID to investigate"),
    triggered_by: str = Query("manual", description="What triggered the investigation")
):
    """Start a new investigation and return the investigation ID"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        investigation_id = await investigation_service.start_investigation(user_id, triggered_by)
        
        return {
            "investigation_id": investigation_id,
            "user_id": user_id,
            "triggered_by": triggered_by,
            "stream_url": f"/investigation/{user_id}/stream?investigation_id={investigation_id}"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to start investigation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start investigation: {str(e)}")


@app.get("/investigation/{investigation_id}/status")
def get_investigation_status(
    investigation_id: str = Path(..., description="Investigation ID")
):
    """Get current investigation status (for reconnection)"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        status = investigation_service.get_investigation_status(investigation_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get investigation status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@app.get("/investigation/{investigation_id}/result")
def get_investigation_result(
    investigation_id: str = Path(..., description="Investigation ID")
):
    """Get completed investigation result"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        result = investigation_service.get_investigation_result(investigation_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Investigation result not found")
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get investigation result: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get result: {str(e)}")


@app.get("/investigation/{investigation_id}/report")
async def get_investigation_report(
    investigation_id: str = Path(..., description="Investigation ID")
):
    """Get the markdown report for an investigation"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        report = await investigation_service.get_investigation_report(investigation_id)
        
        if not report:
            raise HTTPException(status_code=404, detail="Investigation report not found")
        
        return {
            "investigation_id": investigation_id,
            "report": report
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get investigation report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")


@app.get("/investigation/user/{user_id}/history")
def get_user_investigation_history(
    user_id: str = Path(..., description="User ID")
):
    """Get investigation history for a user"""
    try:
        if not investigation_service:
            raise HTTPException(status_code=503, detail="Investigation service not initialized")
        
        history = investigation_service.get_user_investigation_history(user_id)
        
        return {
            "user_id": user_id,
            "investigations": history,
            "total": len(history)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get user investigation history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")


@app.get("/investigation/user/{user_id}/latest")
def get_user_latest_investigation(
    user_id: str = Path(..., description="User ID")
):
    """
    Get the most recent completed investigation for a user.
    
    Returns the full investigation data including:
    - initial_evidence
    - final_assessment
    - tool_calls
    - report_markdown
    - completed_steps
    
    This endpoint is used by the frontend to restore investigation state
    when the user navigates back to the investigation page.
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

