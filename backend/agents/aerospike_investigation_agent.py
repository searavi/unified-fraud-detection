"""
Aerospike Investigation Agent using Synchtron

This agent handles fraud investigation workflows using Aerospike
graph queries and the Synchtron orchestration framework.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import logging
from synchtron import Task, Context
from .base_agent import BaseAerospikeAgent

logger = logging.getLogger(__name__)


class AerospikeInvestigationAgent(BaseAerospikeAgent):
    """
    Investigation agent that performs deep analysis of fraud patterns
    using Aerospike Graph and Synchtron for workflow orchestration.
    """
    
    def __init__(
        self,
        agent_id: str,
        aerospike_config: Dict[str, Any],
        graph_service_url: str = "http://localhost:8182",
        **kwargs
    ):
        """
        Initialize the investigation agent.
        
        Args:
            agent_id: Unique identifier for this agent
            aerospike_config: Aerospike connection configuration
            graph_service_url: URL for Aerospike Graph Service
            **kwargs: Additional arguments for base agent
        """
        super().__init__(
            agent_id=agent_id,
            aerospike_config=aerospike_config,
            set_name="investigations",
            **kwargs
        )
        self.graph_service_url = graph_service_url
    
    async def process_task(self, task: Task, context: Context) -> Dict[str, Any]:
        """
        Process an investigation task.
        
        Args:
            task: The investigation task
            context: The execution context
            
        Returns:
            Investigation result
        """
        task_type = task.get("type")
        
        if task_type == "start_investigation":
            return await self.start_investigation(
                task.get("transaction_id"),
                context
            )
        elif task_type == "analyze_network":
            return await self.analyze_fraud_network(
                task.get("account_id"),
                context
            )
        elif task_type == "find_patterns":
            return await self.find_fraud_patterns(
                task.get("parameters"),
                context
            )
        elif task_type == "get_investigation":
            return await self.get_investigation(
                task.get("investigation_id"),
                context
            )
        else:
            logger.warning(f"Unknown task type: {task_type}")
            return {"error": f"Unknown task type: {task_type}"}
    
    async def start_investigation(
        self,
        transaction_id: str,
        context: Context
    ) -> Dict[str, Any]:
        """
        Start a new fraud investigation.
        
        Args:
            transaction_id: The transaction to investigate
            context: The execution context
            
        Returns:
            Investigation details
        """
        try:
            # Generate investigation ID
            investigation_id = f"inv_{datetime.utcnow().timestamp()}"
            
            # Get transaction details
            transaction = await self.get_record(transaction_id)
            if not transaction:
                return {
                    "success": False,
                    "error": "Transaction not found"
                }
            
            # Create investigation record
            investigation = {
                "investigation_id": investigation_id,
                "transaction_id": transaction_id,
                "status": "active",
                "created_at": datetime.utcnow().isoformat(),
                "findings": [],
                "risk_score": 0,
                "accounts_analyzed": [],
                "devices_analyzed": []
            }
            
            # Perform initial analysis
            network_analysis = await self.analyze_fraud_network(
                transaction.get("sender_id"),
                context
            )
            
            investigation["findings"].append({
                "type": "network_analysis",
                "data": network_analysis,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Calculate overall risk
            investigation["risk_score"] = network_analysis.get("risk_score", 0)
            
            # Store investigation
            await self.put_record(investigation_id, investigation)
            
            logger.info(f"Started investigation: {investigation_id}")
            return {
                "success": True,
                "investigation_id": investigation_id,
                "investigation": investigation
            }
            
        except Exception as e:
            logger.error(f"Error starting investigation for {transaction_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def analyze_fraud_network(
        self,
        account_id: str,
        context: Context,
        depth: int = 2
    ) -> Dict[str, Any]:
        """
        Analyze the fraud network around an account.
        
        Args:
            account_id: The account to analyze
            context: The execution context
            depth: Graph traversal depth
            
        Returns:
            Network analysis results
        """
        try:
            # Get account details
            account = await self.get_record(account_id)
            if not account:
                return {
                    "success": False,
                    "error": "Account not found"
                }
            
            # Analyze connected accounts
            connected_accounts = await self.get_connected_accounts(
                account_id,
                depth
            )
            
            # Analyze connected devices
            connected_devices = await self.get_connected_devices(account_id)
            
            # Identify suspicious patterns
            suspicious_patterns = await self.identify_suspicious_patterns(
                account_id,
                connected_accounts,
                connected_devices
            )
            
            # Calculate network risk score
            risk_score = self.calculate_network_risk(
                account,
                connected_accounts,
                connected_devices,
                suspicious_patterns
            )
            
            return {
                "success": True,
                "account_id": account_id,
                "connected_accounts": connected_accounts,
                "connected_devices": connected_devices,
                "suspicious_patterns": suspicious_patterns,
                "risk_score": risk_score,
                "analyzed_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing network for {account_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_connected_accounts(
        self,
        account_id: str,
        depth: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Get accounts connected through transactions.
        
        Args:
            account_id: The account ID
            depth: Traversal depth
            
        Returns:
            List of connected accounts
        """
        # This would use Aerospike Graph traversal
        # Placeholder implementation
        connected = []
        
        # In real implementation, execute Gremlin query like:
        # g.V(account_id).repeat(both(\'transacted\')).times(depth).dedup()
        
        return connected
    
    async def get_connected_devices(
        self,
        account_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get devices connected to an account.
        
        Args:
            account_id: The account ID
            
        Returns:
            List of connected devices
        """
        # This would query device connections
        # Placeholder implementation
        devices = []
        
        return devices
    
    async def identify_suspicious_patterns(
        self,
        account_id: str,
        connected_accounts: List[Dict[str, Any]],
        connected_devices: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify suspicious patterns in the network.
        
        Args:
            account_id: The account ID
            connected_accounts: Connected accounts
            connected_devices: Connected devices
            
        Returns:
            List of suspicious patterns
        """
        patterns = []
        
        # Check for flagged connections
        flagged_accounts = [
            acc for acc in connected_accounts
            if acc.get("flagged", False)
        ]
        if flagged_accounts:
            patterns.append({
                "pattern": "flagged_connections",
                "severity": "HIGH",
                "count": len(flagged_accounts),
                "details": flagged_accounts
            })
        
        # Check for high-frequency transactions
        # (would analyze transaction timestamps)
        
        # Check for circular transaction patterns
        # (would use graph algorithms)
        
        return patterns
    
    def calculate_network_risk(
        self,
        account: Dict[str, Any],
        connected_accounts: List[Dict[str, Any]],
        connected_devices: List[Dict[str, Any]],
        suspicious_patterns: List[Dict[str, Any]]
    ) -> int:
        """
        Calculate overall network risk score.
        
        Args:
            account: The account data
            connected_accounts: Connected accounts
            connected_devices: Connected devices
            suspicious_patterns: Identified patterns
            
        Returns:
            Risk score (0-100)
        """
        risk = 0
        
        # Base risk from account status
        if account.get("flagged", False):
            risk += 50
        
        # Risk from connections
        flagged_connections = sum(
            1 for acc in connected_accounts
            if acc.get("flagged", False)
        )
        risk += min(flagged_connections * 10, 30)
        
        # Risk from patterns
        for pattern in suspicious_patterns:
            if pattern.get("severity") == "HIGH":
                risk += 20
            elif pattern.get("severity") == "MEDIUM":
                risk += 10
        
        return min(risk, 100)
    
    async def find_fraud_patterns(
        self,
        parameters: Dict[str, Any],
        context: Context
    ) -> Dict[str, Any]:
        """
        Find fraud patterns across the graph.
        
        Args:
            parameters: Search parameters
            context: The execution context
            
        Returns:
            Detected fraud patterns
        """
        try:
            # Extract search parameters
            time_window = parameters.get("time_window_days", 7)
            min_amount = parameters.get("min_amount", 0)
            
            # Search for patterns
            patterns = []
            
            # Pattern 1: Rapid transaction chains
            # Pattern 2: Circular money flows
            # Pattern 3: Sudden account activity spikes
            
            return {
                "success": True,
                "patterns": patterns,
                "parameters": parameters,
                "searched_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error finding fraud patterns: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_investigation(
        self,
        investigation_id: str,
        context: Context
    ) -> Dict[str, Any]:
        """
        Retrieve an investigation by ID.
        
        Args:
            investigation_id: The investigation ID
            context: The execution context
            
        Returns:
            Investigation data
        """
        try:
            investigation = await self.get_record(investigation_id)
            if not investigation:
                return {
                    "success": False,
                    "error": "Investigation not found"
                }
            
            return {
                "success": True,
                "investigation": investigation
            }
            
        except Exception as e:
            logger.error(f"Error retrieving investigation {investigation_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
