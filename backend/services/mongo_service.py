"""
MongoDB-backed replacement for AerospikeService.

Duck-type compatible with the exact method surface main.py and
flagged_account_service.py call for the trimmed "Flagged Users" backend:
connect, close, is_connected, get, put, scan_all, get_user,
get_transactions_for_account, get_account_fact, update_account_fact,
flag_account_in_user, get_flagged_account, get_all_flagged_accounts,
update_flagged_account, put_investigation, get_investigation,
get_user_latest_investigation.

The higher-level domain methods below are copied near-verbatim from
aerospike_service.py's own bodies (they were already pure compositions of
get/put/scan_all/is_connected, no Aerospike-specific plumbing) — so behavior
matches exactly, just backed by MongoDB.

Collections mirror aerospike_service.py's SET_* names, each prefixed
"fraud_" so they coexist safely in a database shared with anything else
(e.g. Mesh's own operational collections). See scripts/seed_mongo.py, which
seeds this same schema directly — no Aerospike, no graph store, no live ML
detection job involved.

Unlike the Agent repo's fraud-node MongoService, this class does NOT expand
short feature-bin names to long ones on read: none of the endpoints this
backend keeps (user profile, flagged-account list/detail, account
resolution, investigation lookup) read the 15/5 short-named ML feature
fields directly — those are only consumed by the investigation agents,
which have their own MongoService in the Agent repo.

Env vars:
  MONGODB_CONNECTION_STRING   Connection string (local docker or cloud).
  MONGODB_DATABASE            Database name (default: fraud_detection) —
                               must match --db-name passed to seed_mongo.py.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False
    MongoClient = None

from services.aerospike_service import (
    SET_USERS,
    SET_FLAGGED_ACCOUNTS,
    SET_ACCOUNT_FACT,
    SET_TRANSACTIONS,
    SET_INVESTIGATIONS,
)

logger = logging.getLogger('fraud_detection.mongo')

MONGO_URI = os.environ.get('MONGODB_CONNECTION_STRING', 'mongodb://localhost:27017')
MONGO_DATABASE = os.environ.get('MONGODB_DATABASE', 'fraud_detection')
COLLECTION_PREFIX = 'fraud_'


class MongoService:
    """MongoDB-backed data service for the trimmed Flagged Users backend."""

    def __init__(self):
        self.client = None
        self.db = None
        self.connected = False

    def connect(self) -> bool:
        if not PYMONGO_AVAILABLE:
            logger.warning("pymongo not available. Install pymongo>=4.6.0.")
            return False
        try:
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[MONGO_DATABASE]
            self.connected = True
            logger.info(f"✅ Connected to MongoDB database '{MONGO_DATABASE}'")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            self.connected = False
            return False

    def close(self):
        if self.client and self.connected:
            try:
                self.client.close()
                self.connected = False
                logger.info("✅ Disconnected from MongoDB")
            except Exception as e:
                logger.warning(f"Error closing MongoDB connection: {e}")

    def is_connected(self) -> bool:
        return self.connected and self.db is not None

    def _collection(self, set_name: str):
        return self.db[f"{COLLECTION_PREFIX}{set_name}"]

    # ------------------------------------------------------------------
    # Generic get/put/scan — everything below is built on these three
    # ------------------------------------------------------------------

    def get(self, set_name: str, key: str) -> Optional[Dict[str, Any]]:
        if not self.is_connected():
            return None
        try:
            doc = self._collection(set_name).find_one({"_id": key})
            if doc is None:
                return None
            return {k: v for k, v in doc.items() if k != "_id"}
        except Exception as e:
            logger.error(f"Error getting {key} from {set_name}: {e}")
            return None

    def put(self, set_name: str, key: str, data: Dict[str, Any]) -> bool:
        if not self.is_connected():
            return False
        try:
            self._collection(set_name).replace_one({"_id": key}, {**data, "_id": key}, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Error putting {key} in {set_name}: {e}")
            return False

    def scan_all(self, set_name: str, limit: int = 10000) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        try:
            docs = self._collection(set_name).find({}).limit(limit)
            return [{k: v for k, v in d.items() if k != "_id"} for d in docs]
        except Exception as e:
            logger.error(f"Error scanning {set_name}: {e}")
            return []

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        return self.get(SET_USERS, user_id)

    def flag_account_in_user(self, user_id: str, account_id: str, is_fraud: bool) -> bool:
        user = self.get_user(user_id)
        if not user or 'accounts' not in user:
            logger.warning(f"User {user_id} not found or has no accounts")
            return False
        if account_id not in user['accounts']:
            logger.warning(f"Account {account_id} not found in user {user_id}")
            return False
        user['accounts'][account_id]['is_fraud'] = is_fraud
        success = self.put(SET_USERS, user_id, user)
        if success:
            logger.info(f"✅ Flagged account {account_id} in user {user_id}: is_fraud={is_fraud}")
        return success

    # ------------------------------------------------------------------
    # Flagged accounts
    # ------------------------------------------------------------------

    def get_flagged_account(self, account_id: str) -> Optional[Dict[str, Any]]:
        return self.get(SET_FLAGGED_ACCOUNTS, account_id)

    def get_all_flagged_accounts(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return self.scan_all(SET_FLAGGED_ACCOUNTS, limit)

    def update_flagged_account(self, account_id: str, updates: Dict[str, Any]) -> bool:
        account = self.get_flagged_account(account_id)
        if not account:
            return False
        account.update(updates)
        account["updated_at"] = datetime.now().isoformat()
        return self.put(SET_FLAGGED_ACCOUNTS, account_id, account)

    # ------------------------------------------------------------------
    # Account facts
    # ------------------------------------------------------------------

    def get_account_fact(self, account_id: str) -> Optional[Dict[str, Any]]:
        return self.get(SET_ACCOUNT_FACT, account_id)

    def update_account_fact(self, account_id: str, features: Dict[str, Any]) -> bool:
        features['account_id'] = account_id
        features['last_computed'] = datetime.now().isoformat()
        return self.put(SET_ACCOUNT_FACT, account_id, features)

    # ------------------------------------------------------------------
    # Transactions — one document per (transaction, side); see
    # scripts/seed_mongo.py for the schema.
    # ------------------------------------------------------------------

    def get_transactions_for_account(self, account_id: str, days: int = 7) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        try:
            cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            docs = self._collection(SET_TRANSACTIONS).find({
                "account_id": account_id,
                "timestamp": {"$gte": cutoff},
            }).sort("timestamp", -1)
            return [{k: v for k, v in d.items() if k != "_id"} for d in docs]
        except Exception as e:
            logger.error(f"Error getting transactions for {account_id}: {e}")
            return []

    # ------------------------------------------------------------------
    # Investigations
    # ------------------------------------------------------------------

    def put_investigation(self, investigation_id: str, data: Dict[str, Any]) -> bool:
        if not self.is_connected():
            return False
        try:
            data["investigation_id"] = investigation_id
            data["stored_at"] = datetime.now().isoformat()
            return self.put(SET_INVESTIGATIONS, investigation_id, data)
        except Exception as e:
            logger.error(f"Error storing investigation {investigation_id}: {e}")
            return False

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        return self.get(SET_INVESTIGATIONS, investigation_id)

    def get_user_latest_investigation(self, user_id: str) -> Optional[Dict[str, Any]]:
        if not self.is_connected():
            return None
        try:
            all_investigations = self.scan_all(SET_INVESTIGATIONS, limit=1000)
            user_investigations = [
                inv for inv in all_investigations if inv.get("user_id") == user_id
            ]
            if not user_investigations:
                return None
            user_investigations.sort(key=lambda x: x.get("completed_at", ""), reverse=True)
            return user_investigations[0]
        except Exception as e:
            logger.error(f"Error getting latest investigation for user {user_id}: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        if not self.is_connected():
            return {"connected": False}
        return {"connected": True}


# Singleton instance
mongo_service = MongoService()
