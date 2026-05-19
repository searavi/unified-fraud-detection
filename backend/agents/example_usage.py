"""
Example usage of Aerospike Agents with Synchtron

This module demonstrates how to initialize and use the Aerospike agents
for fraud detection, transaction processing, and investigation workflows.
"""

import asyncio
import logging
from typing import Dict, Any

from agents.config import AerospikeAgentConfig
from agents import (
    AerospikeFraudAgent,
    AerospikeTransactionAgent,
    AerospikeInvestigationAgent
)
from synchtron import Context

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Main example demonstrating agent usage."""
    
    # Get configurations
    aerospike_config = AerospikeAgentConfig.get_aerospike_config()
    graph_service_url = AerospikeAgentConfig.get_graph_service_url()
    
    # Initialize agents
    fraud_agent = AerospikeFraudAgent(
        agent_id="fraud_agent_1",
        aerospike_config=aerospike_config,
        graph_service_url=graph_service_url
    )
    
    transaction_agent = AerospikeTransactionAgent(
        agent_id="transaction_agent_1",
        aerospike_config=aerospike_config
    )
    
    investigation_agent = AerospikeInvestigationAgent(
        agent_id="investigation_agent_1",
        aerospike_config=aerospike_config,
        graph_service_url=graph_service_url
    )
    
    try:
        # Initialize all agents
        await fraud_agent.initialize()
        await transaction_agent.initialize()
        await investigation_agent.initialize()
        
        logger.info("All agents initialized successfully")
        
        # Example 1: Create a transaction
        context = Context()
        create_task = {
            "type": "create_transaction",
            "data": {
                "sender_id": "account_123",
                "receiver_id": "account_456",
                "amount": 1500.00,
                "currency": "USD",
                "device_id": "device_789"
            }
        }
        
        transaction_result = await transaction_agent.process_task(create_task, context)
        logger.info(f"Transaction created: {transaction_result}")
        
        if transaction_result.get("success"):
            transaction_id = transaction_result["transaction_id"]
            
            # Example 2: Check transaction for fraud
            fraud_check_task = {
                "type": "check_transaction",
                "transaction_id": transaction_id
            }
            
            fraud_result = await fraud_agent.process_task(fraud_check_task, context)
            logger.info(f"Fraud check result: {fraud_result}")
            
            # Example 3: Start investigation if high risk
            if fraud_result.get("risk_score", 0) > 50:
                investigation_task = {
                    "type": "start_investigation",
                    "transaction_id": transaction_id
                }
                
                investigation_result = await investigation_agent.process_task(
                    investigation_task,
                    context
                )
                logger.info(f"Investigation started: {investigation_result}")
        
        # Example 4: Analyze account network
        network_task = {
            "type": "analyze_network",
            "account_id": "account_123"
        }
        
        network_result = await investigation_agent.process_task(network_task, context)
        logger.info(f"Network analysis: {network_result}")
        
        # Example 5: Batch fraud checks
        batch_task = {
            "type": "batch_check",
            "items": ["txn_1", "txn_2", "txn_3"]
        }
        
        batch_result = await fraud_agent.process_task(batch_task, context)
        logger.info(f"Batch check results: {batch_result}")
        
    except Exception as e:
        logger.error(f"Error in agent operations: {e}")
        raise
    
    finally:
        # Cleanup agents
        await fraud_agent.cleanup()
        await transaction_agent.cleanup()
        await investigation_agent.cleanup()
        logger.info("All agents cleaned up")


async def distributed_fraud_detection():
    """
    Example of distributed fraud detection using multiple agents
    coordinated through Synchtron.
    """
    
    aerospike_config = AerospikeAgentConfig.get_aerospike_config()
    
    # Create multiple fraud agents for distributed processing
    agents = []
    for i in range(3):
        agent = AerospikeFraudAgent(
            agent_id=f"fraud_agent_{i}",
            aerospike_config=aerospike_config
        )
        await agent.initialize()
        agents.append(agent)
    
    try:
        # Distribute work across agents
        transactions = [f"txn_{i}" for i in range(100)]
        chunk_size = len(transactions) // len(agents)
        
        tasks = []
        context = Context()
        
        for i, agent in enumerate(agents):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < len(agents) - 1 else len(transactions)
            chunk = transactions[start_idx:end_idx]
            
            task = {
                "type": "batch_check",
                "items": chunk
            }
            
            tasks.append(agent.process_task(task, context))
        
        # Process all tasks concurrently
        results = await asyncio.gather(*tasks)
        
        # Aggregate results
        total_checked = sum(len(r) for r in results)
        flagged = sum(
            1 for result_list in results
            for r in result_list
            if r.get("status") == "flagged"
        )
        
        logger.info(
            f"Distributed check complete: {total_checked} transactions checked, "
            f"{flagged} flagged"
        )
        
    finally:
        # Cleanup all agents
        for agent in agents:
            await agent.cleanup()


async def workflow_orchestration():
    """
    Example of workflow orchestration using Synchtron to coordinate
    multiple agents for end-to-end fraud detection.
    """
    
    aerospike_config = AerospikeAgentConfig.get_aerospike_config()
    graph_service_url = AerospikeAgentConfig.get_graph_service_url()
    
    # Initialize agents
    transaction_agent = AerospikeTransactionAgent(
        agent_id="txn_orchestrator",
        aerospike_config=aerospike_config
    )
    
    fraud_agent = AerospikeFraudAgent(
        agent_id="fraud_orchestrator",
        aerospike_config=aerospike_config,
        graph_service_url=graph_service_url
    )
    
    investigation_agent = AerospikeInvestigationAgent(
        agent_id="inv_orchestrator",
        aerospike_config=aerospike_config,
        graph_service_url=graph_service_url
    )
    
    await transaction_agent.initialize()
    await fraud_agent.initialize()
    await investigation_agent.initialize()
    
    try:
        context = Context()
        
        # Step 1: Create transaction
        txn_task = {
            "type": "create_transaction",
            "data": {
                "sender_id": "account_high_risk",
                "receiver_id": "account_flagged",
                "amount": 5000.00
            }
        }
        
        txn_result = await transaction_agent.process_task(txn_task, context)
        
        if txn_result.get("success"):
            txn_id = txn_result["transaction_id"]
            
            # Step 2: Real-time fraud check
            fraud_task = {
                "type": "check_transaction",
                "transaction_id": txn_id
            }
            
            fraud_result = await fraud_agent.process_task(fraud_task, context)
            
            # Step 3: Conditional investigation
            if fraud_result.get("risk_score", 0) > 70:
                inv_task = {
                    "type": "start_investigation",
                    "transaction_id": txn_id
                }
                
                inv_result = await investigation_agent.process_task(inv_task, context)
                
                # Step 4: Update transaction status
                update_task = {
                    "type": "update_transaction",
                    "transaction_id": txn_id,
                    "updates": {
                        "status": "under_investigation",
                        "investigation_id": inv_result.get("investigation_id")
                    }
                }
                
                await transaction_agent.process_task(update_task, context)
                
                logger.info(
                    f"High-risk transaction {txn_id} flagged and "
                    f"investigation {inv_result.get(\'investigation_id\')} started"
                )
            else:
                # Update transaction as approved
                update_task = {
                    "type": "update_transaction",
                    "transaction_id": txn_id,
                    "updates": {"status": "approved"}
                }
                
                await transaction_agent.process_task(update_task, context)
                logger.info(f"Transaction {txn_id} approved")
    
    finally:
        await transaction_agent.cleanup()
        await fraud_agent.cleanup()
        await investigation_agent.cleanup()


if __name__ == "__main__":
    # Run main example
    asyncio.run(main())
    
    # Uncomment to run other examples:
    # asyncio.run(distributed_fraud_detection())
    # asyncio.run(workflow_orchestration())
