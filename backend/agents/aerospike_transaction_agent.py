"""
Aerospike Transaction Agent using Synchtron

This agent manages transaction processing and validation using
Aerospike and the Synchtron orchestration framework.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
from synchtron import Task, Context
from .base_agent import BaseAerospikeAgent

logger = logging.getLogger(__name__)


class AerospikeTransactionAgent(BaseAerospikeAgent):
    """
    Transaction processing agent that handles transaction validation,
    storage, and retrieval using Aerospike and Synchtron.
    """
    
    def __init__(
        self,
        agent_id: str,
        aerospike_config: Dict[str, Any],
        **kwargs
    ):
        """
        Initialize the transaction agent.
        
        Args:
            agent_id: Unique identifier for this agent
            aerospike_config: Aerospike connection configuration
            **kwargs: Additional arguments for base agent
        """
        super().__init__(
            agent_id=agent_id,
            aerospike_config=aerospike_config,
            set_name="transactions",
            **kwargs
        )
    
    async def process_task(self, task: Task, context: Context) -> Dict[str, Any]:
        """
        Process a transaction-related task.
        
        Args:
            task: The transaction task
            context: The execution context
            
        Returns:
            Task processing result
        """
        task_type = task.get("type")
        
        if task_type == "create_transaction":
            return await self.create_transaction(task.get("data"), context)
        elif task_type == "get_transaction":
            return await self.get_transaction(task.get("transaction_id"), context)
        elif task_type == "update_transaction":
            return await self.update_transaction(
                task.get("transaction_id"),
                task.get("updates"),
                context
            )
        elif task_type == "get_account_transactions":
            return await self.get_account_transactions(
                task.get("account_id"),
                context
            )
        else:
            logger.warning(f"Unknown task type: {task_type}")
            return {"error": f"Unknown task type: {task_type}"}
    
    async def create_transaction(
        self,
        transaction_data: Dict[str, Any],
        context: Context
    ) -> Dict[str, Any]:
        """
        Create and store a new transaction.
        
        Args:
            transaction_data: The transaction data
            context: The execution context
            
        Returns:
            Created transaction with ID
        """
        try:
            # Generate transaction ID if not provided
            transaction_id = transaction_data.get(
                "transaction_id",
                f"txn_{datetime.utcnow().timestamp()}"
            )
            
            # Enrich transaction data
            transaction = {
                **transaction_data,
                "transaction_id": transaction_id,
                "created_at": datetime.utcnow().isoformat(),
                "status": transaction_data.get("status", "pending"),
                "version": 1
            }
            
            # Validate transaction
            validation_result = await self.validate_transaction(transaction, context)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": "Transaction validation failed",
                    "details": validation_result.get("errors", [])
                }
            
            # Store transaction
            await self.put_record(transaction_id, transaction)
            
            logger.info(f"Created transaction: {transaction_id}")
            return {
                "success": True,
                "transaction_id": transaction_id,
                "transaction": transaction
            }
            
        except Exception as e:
            logger.error(f"Error creating transaction: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_transaction(
        self,
        transaction_id: str,
        context: Context
    ) -> Dict[str, Any]:
        """
        Retrieve a transaction by ID.
        
        Args:
            transaction_id: The transaction ID
            context: The execution context
            
        Returns:
            Transaction data or error
        """
        try:
            transaction = await self.get_record(transaction_id)
            if not transaction:
                return {
                    "success": False,
                    "error": "Transaction not found",
                    "transaction_id": transaction_id
                }
            
            return {
                "success": True,
                "transaction": transaction
            }
            
        except Exception as e:
            logger.error(f"Error retrieving transaction {transaction_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def update_transaction(
        self,
        transaction_id: str,
        updates: Dict[str, Any],
        context: Context
    ) -> Dict[str, Any]:
        """
        Update an existing transaction.
        
        Args:
            transaction_id: The transaction ID
            updates: Fields to update
            context: The execution context
            
        Returns:
            Update result
        """
        try:
            # Get existing transaction
            transaction = await self.get_record(transaction_id)
            if not transaction:
                return {
                    "success": False,
                    "error": "Transaction not found",
                    "transaction_id": transaction_id
                }
            
            # Apply updates
            updated_transaction = {
                **transaction,
                **updates,
                "updated_at": datetime.utcnow().isoformat(),
                "version": transaction.get("version", 1) + 1
            }
            
            # Store updated transaction
            await self.put_record(transaction_id, updated_transaction)
            
            logger.info(f"Updated transaction: {transaction_id}")
            return {
                "success": True,
                "transaction_id": transaction_id,
                "transaction": updated_transaction
            }
            
        except Exception as e:
            logger.error(f"Error updating transaction {transaction_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_account_transactions(
        self,
        account_id: str,
        context: Context,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get all transactions for an account.
        
        Args:
            account_id: The account ID
            context: The execution context
            limit: Maximum number of transactions to return
            
        Returns:
            List of transactions
        """
        try:
            # This would typically use a secondary index or scan
            # For demonstration, returning placeholder
            transactions = []
            
            # In a real implementation, you would:
            # 1. Use Aerospike secondary index on sender_id/receiver_id
            # 2. Or maintain a separate set with account transaction lists
            # 3. Or use Aerospike Graph to traverse transaction edges
            
            return {
                "success": True,
                "account_id": account_id,
                "transactions": transactions,
                "count": len(transactions)
            }
            
        except Exception as e:
            logger.error(f"Error getting transactions for account {account_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def validate_transaction(
        self,
        transaction: Dict[str, Any],
        context: Context
    ) -> Dict[str, Any]:
        """
        Validate transaction data.
        
        Args:
            transaction: The transaction to validate
            context: The execution context
            
        Returns:
            Validation result
        """
        errors = []
        
        # Check required fields
        required_fields = ["sender_id", "receiver_id", "amount"]
        for field in required_fields:
            if field not in transaction:
                errors.append(f"Missing required field: {field}")
        
        # Validate amount
        amount = transaction.get("amount", 0)
        if amount <= 0:
            errors.append("Amount must be positive")
        
        # Validate account IDs
        if transaction.get("sender_id") == transaction.get("receiver_id"):
            errors.append("Sender and receiver cannot be the same")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def process_batch(
        self,
        transactions: List[Dict[str, Any]],
        context: Context
    ) -> List[Dict[str, Any]]:
        """
        Process multiple transactions in batch.
        
        Args:
            transactions: List of transaction data
            context: The execution context
            
        Returns:
            List of processing results
        """
        results = []
        for transaction_data in transactions:
            result = await self.create_transaction(transaction_data, context)
            results.append(result)
        
        return results
