"""
Configuration for Aerospike Agents using Synchtron

This module provides configuration management for Aerospike agents.
"""

import os
from typing import Dict, Any


class AerospikeAgentConfig:
    """Configuration manager for Aerospike agents."""
    
    @staticmethod
    def get_aerospike_config() -> Dict[str, Any]:
        """
        Get Aerospike client configuration.
        
        Returns:
            Aerospike configuration dictionary
        """
        return {
            "hosts": [
                (
                    os.getenv("AEROSPIKE_HOST", "localhost"),
                    int(os.getenv("AEROSPIKE_PORT", "3000"))
                )
            ],
            "policies": {
                "timeout": int(os.getenv("AEROSPIKE_TIMEOUT", "1000"))
            }
        }
    
    @staticmethod
    def get_graph_service_url() -> str:
        """
        Get Aerospike Graph Service URL.
        
        Returns:
            Graph service URL
        """
        host = os.getenv("GRAPH_SERVICE_HOST", "localhost")
        port = os.getenv("GRAPH_SERVICE_PORT", "8182")
        return f"http://{host}:{port}"
    
    @staticmethod
    def get_synchtron_config() -> Dict[str, Any]:
        """
        Get Synchtron framework configuration.
        
        Returns:
            Synchtron configuration dictionary
        """
        return {
            "coordinator_url": os.getenv(
                "SYNCHTRON_COORDINATOR",
                "http://localhost:5000"
            ),
            "agent_pool_size": int(os.getenv("AGENT_POOL_SIZE", "10")),
            "task_queue_size": int(os.getenv("TASK_QUEUE_SIZE", "1000")),
            "heartbeat_interval": int(os.getenv("HEARTBEAT_INTERVAL", "30")),
            "enable_telemetry": os.getenv("ENABLE_TELEMETRY", "true").lower() == "true"
        }
    
    @staticmethod
    def get_fraud_agent_config() -> Dict[str, Any]:
        """
        Get fraud detection agent configuration.
        
        Returns:
            Fraud agent configuration
        """
        return {
            "agent_id": os.getenv("FRAUD_AGENT_ID", "fraud_agent_1"),
            "batch_size": int(os.getenv("FRAUD_BATCH_SIZE", "100")),
            "check_interval": int(os.getenv("FRAUD_CHECK_INTERVAL", "60")),
            "risk_threshold": int(os.getenv("FRAUD_RISK_THRESHOLD", "70"))
        }
    
    @staticmethod
    def get_transaction_agent_config() -> Dict[str, Any]:
        """
        Get transaction agent configuration.
        
        Returns:
            Transaction agent configuration
        """
        return {
            "agent_id": os.getenv("TRANSACTION_AGENT_ID", "transaction_agent_1"),
            "batch_size": int(os.getenv("TRANSACTION_BATCH_SIZE", "500")),
            "validation_strict": os.getenv("VALIDATION_STRICT", "true").lower() == "true"
        }
    
    @staticmethod
    def get_investigation_agent_config() -> Dict[str, Any]:
        """
        Get investigation agent configuration.
        
        Returns:
            Investigation agent configuration
        """
        return {
            "agent_id": os.getenv("INVESTIGATION_AGENT_ID", "investigation_agent_1"),
            "max_depth": int(os.getenv("INVESTIGATION_MAX_DEPTH", "3")),
            "analysis_timeout": int(os.getenv("INVESTIGATION_TIMEOUT", "300"))
        }
