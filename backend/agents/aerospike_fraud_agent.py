"""
Aerospike Fraud Detection Agent using Synchtron

This agent specializes in real-time fraud detection using Aerospike
graph capabilities and the Synchtron orchestration framework.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
from synchtron import Task, Context
from .base_agent import BaseAerospikeAgent

logger = logging.getLogger(__name__)


class AerospikeFraudAgent(BaseAerospikeAgent):
    """
    Fraud detection agent that analyzes transactions and accounts
    using Aerospike and Synchtron for distributed processing.
    """
    
    def __init__(
        self,
        agent_id: str,
        aerospike_config: Dict[str, Any],
        graph_service_url: str = "http://localhost:8182",
        **kwargs
    ):
        """
        Initialize the fraud detection agent.
        
        Args:
            agent_id: Unique identifier for this agent
            aerospike_config: Aerospike connection configuration
            graph_service_url: URL for Aerospike Graph Service
            **kwargs: Additional arguments for base agent
        """
        super().__init__(
            agent_id=agent_id,
            aerospike_config=aerospike_config,
            set_name="fraud_checks",
            **kwargs
        )
        self.graph_service_url = graph_service_url
        self.fraud_rules = []
    
    async def initialize(self) -> None:
        """Initialize the fraud agent and load fraud detection rules."""
        await super().initialize()
        await self.load_fraud_rules()
        logger.info(f"Fraud agent {self.agent_id} initialized with {len(self.fraud_rules)} rules")
    
    async def load_fraud_rules(self) -> None:
        """Load fraud detection rules from Aerospike."""
        self.fraud_rules = [
            {
                "rule_id": "RT1",
                "name": "Flagged Account Detection",
                "description": "Detects transactions involving flagged accounts",
                "severity": "HIGH",
                "enabled": True
            },
            {
                "rule_id": "RT2",
                "name": "Flagged Device Connection",
                "description": "Detects accounts connected to flagged devices",
                "severity": "HIGH",
                "enabled": True
            },
            {
                "rule_id": "RT3",
                "name": "Supernode Detection",
                "description": "Identifies accounts with unusually high connectivity",
                "severity": "MEDIUM",
                "enabled": True
            }
        ]
    
    async def process_task(self, task: Task, context: Context) -> Dict[str, Any]:
        """
        Process a fraud detection task.
        
        Args:
            task: The fraud detection task
            context: The execution context
            
        Returns:
            Fraud analysis result
        """
        task_type = task.get("type")
        
        if task_type == "check_transaction":
            return await self.check_transaction(task.get("transaction_id"), context)
        elif task_type == "check_account":
            return await self.check_account(task.get("account_id"), context)
        elif task_type == "batch_check":
            return await self.batch_fraud_check(task.get("items"), context)
        else:
            logger.warning(f"Unknown task type: {task_type}")
            return {"error": f"Unknown task type: {task_type}"}
    
    async def check_transaction(
        self,
        transaction_id: str,
        context: Context
    ) -> Dict[str, Any]:
        """
        Check a transaction for fraud indicators.
        
        Args:
            transaction_id: The transaction to check
            context: The execution context
            
        Returns:
            Fraud check result with risk score and flags
        """
        try:
            # Retrieve transaction data
            transaction = await self.get_record(transaction_id)
            if not transaction:
                return {
                    "transaction_id": transaction_id,
                    "status": "not_found",
                    "risk_score": 0
                }
            
            # Run fraud detection rules
            flags = []
            risk_score = 0
            
            for rule in self.fraud_rules:
                if not rule["enabled"]:
                    continue
                    
                result = await self.apply_rule(rule, transaction, context)
                if result["triggered"]:
                    flags.append({
                        "rule_id": rule["rule_id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "details": result.get("details", {})
                    })
                    risk_score += result.get("risk_score", 10)
            
            # Store fraud check result
            check_result = {
                "transaction_id": transaction_id,
                "checked_at": datetime.utcnow().isoformat(),
                "risk_score": min(risk_score, 100),
                "flags": flags,
                "status": "flagged" if flags else "clean"
            }
            
            await self.put_record(
                f"fraud_check_{transaction_id}",
                check_result
            )
            
            return check_result
            
        except Exception as e:
            logger.error(f"Error checking transaction {transaction_id}: {e}")
            return {
                "transaction_id": transaction_id,
                "status": "error",
                "error": str(e)
            }
    
    async def check_account(
        self,
        account_id: str,
        context: Context
    ) -> Dict[str, Any]:
        """
        Check an account for fraud indicators.
        
        Args:
            account_id: The account to check
            context: The execution context
            
        Returns:
            Account fraud check result
        """
        try:
            account = await self.get_record(account_id)
            if not account:
                return {
                    "account_id": account_id,
                    "status": "not_found"
                }
            
            # Check if account is flagged
            is_flagged = account.get("flagged", False)
            
            # Get account transaction history
            transaction_count = account.get("transaction_count", 0)
            
            # Calculate risk indicators
            risk_indicators = {
                "is_flagged": is_flagged,
                "transaction_count": transaction_count,
                "account_age_days": account.get("account_age_days", 0),
                "recent_flags": account.get("recent_flags", 0)
            }
            
            return {
                "account_id": account_id,
                "status": "flagged" if is_flagged else "active",
                "risk_indicators": risk_indicators,
                "checked_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error checking account {account_id}: {e}")
            return {
                "account_id": account_id,
                "status": "error",
                "error": str(e)
            }
    
    async def apply_rule(
        self,
        rule: Dict[str, Any],
        transaction: Dict[str, Any],
        context: Context
    ) -> Dict[str, Any]:
        """
        Apply a fraud detection rule to a transaction.
        
        Args:
            rule: The fraud rule to apply
            transaction: The transaction data
            context: The execution context
            
        Returns:
            Rule application result
        """
        rule_id = rule["rule_id"]
        
        if rule_id == "RT1":
            # Check for flagged accounts
            sender_id = transaction.get("sender_id")
            receiver_id = transaction.get("receiver_id")
            
            sender = await self.get_record(sender_id) if sender_id else None
            receiver = await self.get_record(receiver_id) if receiver_id else None
            
            flagged = (
                (sender and sender.get("flagged", False)) or
                (receiver and receiver.get("flagged", False))
            )
            
            return {
                "triggered": flagged,
                "risk_score": 50 if flagged else 0,
                "details": {
                    "sender_flagged": sender.get("flagged", False) if sender else False,
                    "receiver_flagged": receiver.get("flagged", False) if receiver else False
                }
            }
        
        elif rule_id == "RT2":
            # Check for flagged device connections
            device_id = transaction.get("device_id")
            if device_id:
                device = await self.get_record(device_id)
                if device and device.get("flagged", False):
                    return {
                        "triggered": True,
                        "risk_score": 40,
                        "details": {"device_id": device_id}
                    }
            
            return {"triggered": False, "risk_score": 0}
        
        elif rule_id == "RT3":
            # Check for supernode patterns
            amount = transaction.get("amount", 0)
            if amount > 10000:  # High value transaction
                return {
                    "triggered": True,
                    "risk_score": 30,
                    "details": {"amount": amount, "reason": "high_value"}
                }
            
            return {"triggered": False, "risk_score": 0}
        
        return {"triggered": False, "risk_score": 0}
    
    async def batch_fraud_check(
        self,
        items: List[str],
        context: Context
    ) -> List[Dict[str, Any]]:
        """
        Perform batch fraud checks on multiple items.
        
        Args:
            items: List of transaction or account IDs
            context: The execution context
            
        Returns:
            List of fraud check results
        """
        results = []
        for item_id in items:
            result = await self.check_transaction(item_id, context)
            results.append(result)
        
        return results
