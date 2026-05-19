"""
Base Aerospike Agent using Synchtron Python Library

This module provides the base class for all Aerospike agents that use
the Synchtron library for distributed orchestration and coordination.
"""

from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
import aerospike
from synchtron import Agent, Task, Context
import logging

logger = logging.getLogger(__name__)


class BaseAerospikeAgent(Agent, ABC):
    """
    Base class for Aerospike agents using Synchtron framework.
    
    Provides common functionality for connecting to Aerospike,
    managing tasks, and coordinating with other agents.
    """
    
    def __init__(
        self,
        agent_id: str,
        aerospike_config: Dict[str, Any],
        namespace: str = "test",
        set_name: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize the base Aerospike agent.
        
        Args:
            agent_id: Unique identifier for this agent
            aerospike_config: Aerospike connection configuration
            namespace: Aerospike namespace to use
            set_name: Aerospike set name to use
            **kwargs: Additional arguments for Synchtron Agent
        """
        super().__init__(agent_id=agent_id, **kwargs)
        self.aerospike_config = aerospike_config
        self.namespace = namespace
        self.set_name = set_name
        self.client: Optional[aerospike.Client] = None
        
    async def initialize(self) -> None:
        """Initialize the agent and connect to Aerospike."""
        try:
            self.client = aerospike.client(self.aerospike_config).connect()
            logger.info(f"Agent {self.agent_id} connected to Aerospike")
            await super().initialize()
        except Exception as e:
            logger.error(f"Failed to connect to Aerospike: {e}")
            raise
    
    async def cleanup(self) -> None:
        """Clean up resources and close Aerospike connection."""
        if self.client:
            self.client.close()
            logger.info(f"Agent {self.agent_id} disconnected from Aerospike")
        await super().cleanup()
    
    def get_key(self, primary_key: str) -> tuple:
        """
        Create an Aerospike key tuple.
        
        Args:
            primary_key: The primary key value
            
        Returns:
            Aerospike key tuple (namespace, set, pk)
        """
        return (self.namespace, self.set_name, primary_key)
    
    async def get_record(self, primary_key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a record from Aerospike.
        
        Args:
            primary_key: The primary key of the record
            
        Returns:
            The record data or None if not found
        """
        try:
            key = self.get_key(primary_key)
            _, _, bins = self.client.get(key)
            return bins
        except aerospike.exception.RecordNotFound:
            logger.warning(f"Record not found: {primary_key}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving record {primary_key}: {e}")
            raise
    
    async def put_record(
        self,
        primary_key: str,
        data: Dict[str, Any],
        ttl: int = 0
    ) -> None:
        """
        Store a record in Aerospike.
        
        Args:
            primary_key: The primary key of the record
            data: The record data to store
            ttl: Time to live in seconds (0 = no expiration)
        """
        try:
            key = self.get_key(primary_key)
            self.client.put(key, data, meta={"ttl": ttl})
            logger.debug(f"Stored record: {primary_key}")
        except Exception as e:
            logger.error(f"Error storing record {primary_key}: {e}")
            raise
    
    async def delete_record(self, primary_key: str) -> bool:
        """
        Delete a record from Aerospike.
        
        Args:
            primary_key: The primary key of the record
            
        Returns:
            True if record was deleted, False if not found
        """
        try:
            key = self.get_key(primary_key)
            self.client.remove(key)
            logger.debug(f"Deleted record: {primary_key}")
            return True
        except aerospike.exception.RecordNotFound:
            logger.warning(f"Record not found for deletion: {primary_key}")
            return False
        except Exception as e:
            logger.error(f"Error deleting record {primary_key}: {e}")
            raise
    
    @abstractmethod
    async def process_task(self, task: Task, context: Context) -> Any:
        """
        Process a task assigned to this agent.
        
        Args:
            task: The task to process
            context: The execution context
            
        Returns:
            Task processing result
        """
        pass
    
    async def execute(self, context: Context) -> Any:
        """
        Execute the agent\'s main logic.
        
        Args:
            context: The execution context
            
        Returns:
            Execution result
        """
        tasks = context.get("tasks", [])
        results = []
        
        for task in tasks:
            result = await self.process_task(task, context)
            results.append(result)
        
        return results
