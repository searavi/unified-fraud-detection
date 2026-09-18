#!/usr/bin/env python3
"""
Seed MongoDB directly with users, accounts, devices, transactions, and
pre-scored flagged accounts — skipping Aerospike, the graph store, and the
live bulk-load/inject/compute-features/detect pipeline entirely.

Why this exists: the live pipeline's detect() step is unreliable by default
(see backend/services/flagged_account_service.py's 7-day cooldown window vs.
transaction_injector.py's 30-day spread — most injected fraud patterns land
outside the window the detector actually scores). This script sidesteps that
by generating fraud bursts concentrated INSIDE the scoring window and by
reusing the app's own feature/scoring code (services.feature_service,
services.ml_service) directly, so the resulting flagged_accounts records are
scored with the exact same rules the real app uses — just computed once,
here, instead of depending on the live job.

Mongo schema written (collections, all prefixed to coexist safely in a
database shared with anything else — e.g. Mesh's own operational database):

  fraud_users            one doc per user; embeds nested `accounts` and
                          `devices` maps, mirroring the app's user record
  fraud_transactions     one doc per (transaction, side) — two docs per
                          transaction, one for the sender ("out"), one for
                          the receiver ("in"); this is a Mongo-native
                          flattening of the old per-account/per-day KV
                          bucket, not a field-for-field port
  fraud_account_fact     one doc per account_id — the 15 computed features
  fraud_device_fact      one doc per device_id — the 5 computed features
  fraud_flagged_accounts one doc per flagged user_id — same shape as
                          FlaggedAccountService._flag_user_with_accounts()

Usage:
  python scripts/seed_mongo.py --mongo-uri "mongodb://localhost:27017" \\
      --db-name fraud_detection --users 60 --fraud-users 12

Requires: faker (already in backend/requirements.txt), pymongo (added
alongside this script — see backend/requirements.txt).
"""

import argparse
import math
import random
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from faker import Faker

SCRIPT_DIR = Path(__file__).resolve().parent
# Repo layout: <root>/scripts/seed_mongo.py, sibling <root>/backend/. The AWS backend image
# instead flattens this to /backend/scripts/seed_mongo.py with /backend/services/ directly
# beside it (backend.Dockerfile COPYs scripts/seed_mongo.py alongside ./backend's own contents,
# for running this via `ecs run-task` inside the VPC — see backend.Dockerfile's comment). Detect
# which layout is actually on disk rather than assuming the repo one.
_repo_layout_backend = SCRIPT_DIR.parent / "backend"
BACKEND_DIR = _repo_layout_backend if _repo_layout_backend.is_dir() else SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

from generate_user_data import (  # noqa: E402
    REGIONAL_DATA,
    DEVICE_TYPES,
    OPERATING_SYSTEMS,
    BROWSERS,
    ACCOUNT_TYPES,
)
from services.feature_service import FeatureService  # noqa: E402
from services.ml_service import ml_model_service  # noqa: E402

try:
    from pymongo import MongoClient
except ImportError:
    print("pymongo is required: pip install pymongo>=4.6.0", file=sys.stderr)
    raise

FRAUD_TYPOLOGIES = ["velocity_anomaly", "amount_anomaly", "new_account_fraud", "fraud_ring"]
RING_SIZE = 14


def now() -> datetime:
    return datetime.now()


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class MongoFraudSeeder:
    def __init__(self, region: str, window_days: int, risk_threshold: float, rng: random.Random):
        self.region = region
        self.window_days = window_days
        self.risk_threshold = risk_threshold
        self.rng = rng
        self.config = REGIONAL_DATA[region]
        self.faker: Faker = self.config["faker"]

        self.users: List[Dict[str, Any]] = []
        # account_id/device_id -> owning user_id, used while building nested maps
        self.account_owner: Dict[str, str] = {}
        self.device_owner: Dict[str, str] = {}
        self.account_created: Dict[str, datetime] = {}
        # account_id -> list of transaction-side docs (both directions)
        self.account_txns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.flat_transactions: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Profile / account / device generation
    # ------------------------------------------------------------------

    def _generate_phone(self) -> str:
        r = self.rng
        if self.region == "american":
            return f"+1-{r.randint(200, 999)}-{r.randint(200, 999)}-{r.randint(1000, 9999)}"
        if self.region == "indian":
            return f"+91-{r.randint(70000, 99999)}-{r.randint(10000, 99999)}"
        if self.region == "en_GB":
            return f"+44-{r.randint(10, 99)}-{r.randint(1000, 9999)}-{r.randint(100000, 999999)}"
        if self.region == "en_AU":
            return f"+61-{r.randint(2, 9)}{r.randint(10000000, 99999999)}"
        if self.region == "zh_CN":
            return f"+86-{r.randint(10, 99)}-{r.randint(10000000, 99999999)}"
        return f"+1-{r.randint(200, 999)}-{r.randint(200, 999)}-{r.randint(1000, 9999)}"

    def _make_device(self, device_num: int) -> Tuple[str, Dict[str, Any]]:
        device_id = f"DEV{str(device_num).zfill(6)}"
        device_type = self.rng.choice(DEVICE_TYPES)
        first_seen = now() - timedelta(days=self.rng.randint(30, 500))
        device = {
            "type": device_type,
            "os": self.rng.choice(OPERATING_SYSTEMS[device_type]),
            "browser": self.rng.choice(BROWSERS[device_type]),
            "fingerprint": self.faker.sha256(),
            "first_seen": iso(first_seen),
            "last_login": iso(now() - timedelta(days=self.rng.randint(0, 5))),
            "login_count": self.rng.randint(5, 200),
            "is_fraud": False,
        }
        return device_id, device

    def generate_users(self, num_users: int, num_fraud_users: int) -> List[str]:
        """Generate users + accounts + devices. Returns the user_ids chosen as the fraud cohort."""
        device_counter = 0
        fraud_user_indices = set(
            self.rng.sample(range(num_users), min(num_fraud_users, num_users))
        )
        fraud_user_ids: List[str] = []

        # A handful of shared-device groups among non-fraud users, for realistic
        # device-exposure signal without it being the thing that drives flagging.
        shared_group_indices = set()
        num_groups = min(3, max(0, (num_users - num_fraud_users) // 15))
        available = [i for i in range(num_users) if i not in fraud_user_indices]
        for _ in range(num_groups):
            if len(available) < 2:
                break
            group = self.rng.sample(available, 2)
            for idx in group:
                shared_group_indices.add(idx)
                available.remove(idx)
        shared_device_id, shared_device = self._make_device(999000)

        for i in range(num_users):
            user_id = f"U{str(i + 1).zfill(6)}"
            is_fraud_user = i in fraud_user_indices
            if is_fraud_user:
                fraud_user_ids.append(user_id)

            name = self.faker.name()
            signup_days_ago = self.rng.randint(0, 730)
            user = {
                "user_id": user_id,
                "name": name,
                "email": f"{name.lower().replace(' ', '.')}@{self.faker.domain_name()}",
                "phone": self._generate_phone(),
                "age": self.rng.randint(18, 70),
                "location": self.rng.choice(self.config["cities"]),
                "occupation": self.rng.choice(self.config["occupations"]),
                "risk_score": 0.0,
                "signup_date": iso(now() - timedelta(days=signup_days_ago)),
                "created_at": iso(now() - timedelta(days=signup_days_ago)),
                "accounts": {},
                "devices": {},
                "wf_status": None,
                "flagged_date": None,
                "assigned_analyst": None,
                "resolution": None,
                "resolution_date": None,
                "resolution_notes": None,
            }

            # Accounts: fraud/new-account typologies get a freshly-created account;
            # everyone else gets an established one so lifecycle rules don't fire
            # on ordinary background users.
            num_accounts = self.rng.choices([1, 2, 3], weights=[0.5, 0.35, 0.15])[0]
            for a in range(num_accounts):
                account_id = f"A{str(i + 1).zfill(6)}{str(a + 1).zfill(2)}"
                account_type = self.rng.choice(ACCOUNT_TYPES)
                is_new_account = is_fraud_user and a == 0
                created_days_ago = (
                    self.rng.randint(0, 20) if is_new_account else self.rng.randint(45, 1000)
                )
                created_date = now() - timedelta(days=created_days_ago)
                account = {
                    "type": account_type,
                    "balance": round(self.rng.uniform(100, 50000), 2),
                    "bank_name": self.rng.choice(self.config["banks"]),
                    "status": "active",
                    "created_date": iso(created_date),
                    "is_fraud": False,
                }
                user["accounts"][account_id] = account
                self.account_owner[account_id] = user_id
                self.account_created[account_id] = created_date

            # Devices
            if i in shared_group_indices:
                user["devices"][shared_device_id] = dict(shared_device)
                self.device_owner.setdefault(shared_device_id, user_id)
            num_devices = self.rng.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0]
            for _ in range(num_devices):
                device_counter += 1
                device_id, device = self._make_device(device_counter)
                user["devices"][device_id] = device
                self.device_owner[device_id] = user_id

            self.users.append(user)

        return fraud_user_ids

    # ------------------------------------------------------------------
    # Transaction generation
    # ------------------------------------------------------------------

    def _record_transaction(
        self,
        sender_account: str,
        receiver_account: str,
        amount: float,
        timestamp: datetime,
        txn_type: str = "transfer",
    ) -> None:
        txn_id = str(uuid.uuid4())
        sender_user = self.account_owner.get(sender_account, "")
        receiver_user = self.account_owner.get(receiver_account, "")
        # Never let a transaction predate either party's account creation.
        earliest = max(
            self.account_created.get(sender_account, timestamp),
            self.account_created.get(receiver_account, timestamp),
        )
        if timestamp < earliest:
            timestamp = earliest
        base = {
            "txn_id": txn_id,
            "timestamp": iso(timestamp),
            "amount": round(amount, 2),
            "type": txn_type,
            "method": "electronic_transfer",
            "location": self.rng.choice(self.config["cities"]),
            "status": "completed",
        }
        out_doc = {
            **base,
            "account_id": sender_account,
            "direction": "out",
            "counterparty": receiver_account,
            "user_id": sender_user,
            "counterparty_user_id": receiver_user,
        }
        in_doc = {
            **base,
            "account_id": receiver_account,
            "direction": "in",
            "counterparty": sender_account,
            "user_id": receiver_user,
            "counterparty_user_id": sender_user,
        }
        self.account_txns[sender_account].append(out_doc)
        self.account_txns[receiver_account].append(in_doc)
        self.flat_transactions.append(out_doc)
        self.flat_transactions.append(in_doc)

    def generate_background_activity(self) -> None:
        """Light, unremarkable transaction activity for every account — keeps
        normal accounts well clear of the flag threshold while giving the LLM
        investigation something non-empty to look at for cleared accounts too."""
        all_accounts = list(self.account_owner.keys())
        if len(all_accounts) < 2:
            return
        window_start = now() - timedelta(days=self.window_days)
        for account_id in all_accounts:
            num_txns = self.rng.randint(0, 5)
            for _ in range(num_txns):
                receiver = self.rng.choice([a for a in all_accounts if a != account_id])
                amount = self.rng.uniform(50, 3000)
                # Never backdate a transaction before either party's account existed.
                earliest = max(
                    window_start,
                    self.account_created.get(account_id, window_start),
                    self.account_created.get(receiver, window_start),
                )
                span_seconds = max(0.0, (now() - earliest).total_seconds())
                ts = earliest + timedelta(seconds=self.rng.uniform(0, span_seconds))
                self._record_transaction(account_id, receiver, amount, ts)

    def _first_account_of(self, user: Dict[str, Any]) -> str:
        return next(iter(user["accounts"].keys()))

    def generate_velocity_anomaly(self, user: Dict[str, Any], all_accounts: List[str]) -> None:
        account_id = self._first_account_of(user)
        others = [a for a in all_accounts if a != account_id]
        # One concentrated 24h burst plus a spread tail — clears txn_out_high (100)
        # AND txn_24h_peak_high (50) at once, not just one of them.
        burst_day = self.rng.uniform(1, max(1, self.window_days - 1))
        for _ in range(90):
            receiver = self.rng.choice(others)
            ts = now() - timedelta(days=burst_day, hours=self.rng.uniform(0, 23))
            self._record_transaction(account_id, receiver, self.rng.uniform(100, 2000), ts)
        for _ in range(60):
            receiver = self.rng.choice(others)
            ts = now() - timedelta(days=self.rng.uniform(0, self.window_days))
            self._record_transaction(account_id, receiver, self.rng.uniform(100, 2000), ts)

    def generate_amount_anomaly(self, user: Dict[str, Any], all_accounts: List[str]) -> None:
        account_id = self._first_account_of(user)
        others = [a for a in all_accounts if a != account_id]
        for _ in range(14):
            receiver = self.rng.choice(others)
            ts = now() - timedelta(days=self.rng.uniform(0, min(2, self.window_days)))
            self._record_transaction(account_id, receiver, self.rng.uniform(5000, 40000), ts)

    def generate_new_account_fraud(self, user: Dict[str, Any], all_accounts: List[str]) -> None:
        account_id = self._first_account_of(user)
        others = [a for a in all_accounts if a != account_id]
        for _ in range(20):
            receiver = self.rng.choice(others)
            ts = now() - timedelta(hours=self.rng.uniform(0, 20))
            self._record_transaction(account_id, receiver, self.rng.uniform(1000, 9000), ts)

    def generate_fraud_ring(self, ring_users: List[Dict[str, Any]]) -> None:
        ring_accounts = [self._first_account_of(u) for u in ring_users]
        for _ in range(len(ring_accounts) * 25):
            sender, receiver = self.rng.sample(ring_accounts, 2)
            amount = self.rng.uniform(2000, 9999)
            ts = now() - timedelta(days=self.rng.uniform(0, self.window_days))
            self._record_transaction(sender, receiver, amount, ts)

    def generate_fraud_activity(self, fraud_user_ids: List[str]) -> None:
        all_accounts = list(self.account_owner.keys())
        users_by_id = {u["user_id"]: u for u in self.users}

        # A ring needs enough members for its own unique-recipient count to
        # clear unique_recipients_high (10) — a ring of size N has at most
        # N-1 possible distinct in-ring counterparties, so a ring below ~10
        # members reliably under-scores on the counterparty category. Below
        # that, every fraud user gets a solo typology instead (each already
        # tuned to clear threshold alone) rather than being folded into an
        # undersized ring that might not clear.
        MIN_RING_SIZE = 10
        if len(fraud_user_ids) >= MIN_RING_SIZE:
            ring_user_ids = fraud_user_ids[: min(RING_SIZE, len(fraud_user_ids))]
            remaining = fraud_user_ids[len(ring_user_ids):]
            self.generate_fraud_ring([users_by_id[uid] for uid in ring_user_ids])
        else:
            remaining = fraud_user_ids

        typology_cycle = ["velocity_anomaly", "amount_anomaly", "new_account_fraud"]
        for i, uid in enumerate(remaining):
            typology = typology_cycle[i % len(typology_cycle)]
            user = users_by_id[uid]
            if typology == "velocity_anomaly":
                self.generate_velocity_anomaly(user, all_accounts)
            elif typology == "amount_anomaly":
                self.generate_amount_anomaly(user, all_accounts)
            else:
                self.generate_new_account_fraud(user, all_accounts)

    # ------------------------------------------------------------------
    # Feature computation + scoring (reuses the app's own logic verbatim)
    # ------------------------------------------------------------------

    def compute_and_score(self) -> Tuple[Dict[str, Dict], Dict[str, Dict], List[Dict]]:
        feature_service = FeatureService(aerospike_service=None)
        cache = feature_service._build_relationship_cache(self.users)

        account_facts: Dict[str, Dict[str, Any]] = {}
        for account_id in cache["all_account_ids"]:
            txns = self.account_txns.get(account_id, [])
            features = feature_service._compute_features_from_data(
                account_id, txns, existing_fact={}, window_days=self.window_days, cache=cache
            )
            prediction = ml_model_service.predict_account_risk(features)
            features["account_id"] = account_id
            features["risk_score"] = prediction["risk_score"]
            features["last_computed"] = iso(now())
            account_facts[account_id] = features

        device_facts: Dict[str, Dict[str, Any]] = {}
        for device_id in cache["all_device_ids"]:
            features = feature_service._compute_device_features_cached(
                device_id, cache, account_facts, self.window_days
            )
            flagging = ml_model_service.evaluate_device_flagging(features)
            features["device_id"] = device_id
            features["watchlist"] = flagging["watchlist"]
            features["last_computed"] = iso(now())
            device_facts[device_id] = features

        flagged_accounts: List[Dict[str, Any]] = []
        for user in self.users:
            account_ids = list(user["accounts"].keys())
            if not account_ids:
                continue
            account_predictions = []
            for account_id in account_ids:
                fact = account_facts.get(account_id, {})
                prediction = ml_model_service.predict_account_risk(fact)
                prediction["account_id"] = account_id
                account_predictions.append(prediction)

            user_prediction = ml_model_service.predict_user_risk(account_predictions)
            risk_score = user_prediction["risk_score"]
            if risk_score >= self.risk_threshold:
                highest_account = user_prediction.get("highest_risk_account", {})
                flagged_accounts.append({
                    "account_id": highest_account.get("account_id", user["user_id"]),
                    "user_id": user["user_id"],
                    "account_holder": user.get("name", "Unknown"),
                    "email": user.get("email", ""),
                    "risk_score": risk_score,
                    "flag_reason": user_prediction.get("reason", ""),
                    "risk_factors": user_prediction.get("risk_factors", []),
                    "flagged_date": iso(now()),
                    "status": "pending_review",
                    "account_count": user_prediction.get("account_count", 0),
                    "highest_risk_account_id": highest_account.get("account_id", ""),
                    "account_predictions": [
                        {"account_id": p.get("account_id"), "risk_score": p.get("risk_score")}
                        for p in account_predictions
                    ],
                    "model_version": user_prediction.get("model_version", "unknown"),
                    "confidence": user_prediction.get("confidence", 0),
                })

        return account_facts, device_facts, flagged_accounts

    # ------------------------------------------------------------------
    # Mongo write
    # ------------------------------------------------------------------

    def write_to_mongo(
        self,
        mongo_uri: str,
        db_name: str,
        account_facts: Dict[str, Dict],
        device_facts: Dict[str, Dict],
        flagged_accounts: List[Dict],
        clear_first: bool,
    ) -> None:
        client = MongoClient(mongo_uri)
        db = client[db_name]

        if clear_first:
            for coll in (
                "fraud_users",
                "fraud_transactions",
                "fraud_account_fact",
                "fraud_device_fact",
                "fraud_flagged_accounts",
            ):
                db[coll].delete_many({})

        if self.users:
            db["fraud_users"].insert_many(
                [{**u, "_id": u["user_id"]} for u in self.users]
            )
        if self.flat_transactions:
            db["fraud_transactions"].insert_many(self.flat_transactions)
        if account_facts:
            db["fraud_account_fact"].insert_many(
                [{**f, "_id": aid} for aid, f in account_facts.items()]
            )
        if device_facts:
            db["fraud_device_fact"].insert_many(
                [{**f, "_id": did} for did, f in device_facts.items()]
            )
        if flagged_accounts:
            db["fraud_flagged_accounts"].insert_many(
                [{**f, "_id": f["user_id"]} for f in flagged_accounts]
            )

        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Seed MongoDB with users/accounts/devices/transactions and pre-scored flagged accounts."
    )
    parser.add_argument("--mongo-uri", required=True, help="MongoDB connection string (local docker or cloud)")
    parser.add_argument("--db-name", default="fraud_detection", help="Database to write into (default: fraud_detection)")
    parser.add_argument("--users", type=int, default=60, help="Total number of users to generate (default: 60)")
    parser.add_argument("--fraud-users", type=int, default=15, help="Number of users to seed as flagged/fraudulent (default: 15)")
    parser.add_argument("--region", choices=list(REGIONAL_DATA.keys()), default="american")
    parser.add_argument("--window-days", type=int, default=7, help="Must match the app's detection window (cooldown_days, default 7)")
    parser.add_argument("--risk-threshold", type=float, default=50, help="Must match flagged_account_service's risk_threshold (default 50)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--clear", action="store_true", help="Delete existing fraud_* documents before seeding")

    args = parser.parse_args()

    Faker.seed(args.seed)
    rng = random.Random(args.seed)

    seeder = MongoFraudSeeder(args.region, args.window_days, args.risk_threshold, rng)

    print(f"Generating {args.users} users ({args.fraud_users} designated fraud cohort)...")
    fraud_user_ids = seeder.generate_users(args.users, args.fraud_users)

    print("Generating background transaction activity...")
    seeder.generate_background_activity()

    print(f"Generating fraud typology activity for {len(fraud_user_ids)} users...")
    seeder.generate_fraud_activity(fraud_user_ids)

    print("Computing account/device features and scoring (reusing services.feature_service / services.ml_service)...")
    account_facts, device_facts, flagged_accounts = seeder.compute_and_score()

    flagged_ids = {f["user_id"] for f in flagged_accounts}
    missed = [uid for uid in fraud_user_ids if uid not in flagged_ids]
    if missed:
        print(f"WARNING: {len(missed)} designated fraud users did not clear the risk threshold: {missed}")
        print("Consider raising typology intensity in generate_fraud_activity() or lowering --risk-threshold.")

    print(f"Writing to MongoDB ({args.db_name} @ {args.mongo_uri})...")
    seeder.write_to_mongo(
        args.mongo_uri, args.db_name, account_facts, device_facts, flagged_accounts, args.clear
    )

    print(
        f"\nDone: {len(seeder.users)} users, {len(seeder.flat_transactions)} transaction docs, "
        f"{len(account_facts)} account facts, {len(device_facts)} device facts, "
        f"{len(flagged_accounts)} flagged users."
    )
    for f in sorted(flagged_accounts, key=lambda x: -x["risk_score"]):
        print(f"  {f['user_id']}  risk={f['risk_score']:.1f}  {f['flag_reason']}")


if __name__ == "__main__":
    main()
