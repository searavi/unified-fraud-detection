# Aerospike Agents with Synchtron

This directory contains Aerospike agents built using the Synchtron Python library for distributed orchestration and coordination in the fraud detection system.

## Overview

The agents provide specialized capabilities for:
- **Fraud Detection**: Real-time fraud analysis using graph-based detection rules
- **Transaction Processing**: Validation, storage, and management of transactions
- **Investigation**: Deep analysis of fraud patterns and network connections

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Synchtron Coordinator                   │
│              (Distributed Task Orchestration)            │
└─────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  Fraud   │    │Transaction│   │Investigation│
    │  Agent   │    │   Agent   │   │   Agent    │
    └──────────┘    └──────────┘    └──────────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │   Aerospike DB      │
                │   + Graph Service   │
                └─────────────────────┘
```

## Agents

### BaseAerospikeAgent

Base class providing common functionality for all agents:
- Aerospike connection management
- Record CRUD operations
- Task processing framework
- Lifecycle management (initialize/cleanup)

### AerospikeFraudAgent

Specialized agent for fraud detection:
- Real-time transaction fraud checks
- Account risk assessment
- Fraud rule application (RT1, RT2, RT3)
- Batch fraud detection
- Integration with Aerospike Graph for pattern detection

**Key Methods:**
- `check_transaction()`: Analyze a transaction for fraud indicators
- `check_account()`: Assess account risk profile
- `apply_rule()`: Execute fraud detection rules
- `batch_fraud_check()`: Process multiple items concurrently

### AerospikeTransactionAgent

Agent for transaction lifecycle management:
- Transaction creation and validation
- Transaction updates and status management
- Account transaction history retrieval
- Batch transaction processing

**Key Methods:**
- `create_transaction()`: Create and validate new transactions
- `get_transaction()`: Retrieve transaction details
- `update_transaction()`: Update transaction status/data
- `get_account_transactions()`: Get transaction history

### AerospikeInvestigationAgent

Agent for fraud investigation workflows:
- Investigation orchestration
- Network analysis using graph traversals
- Fraud pattern identification
- Risk scoring based on network topology

**Key Methods:**
- `start_investigation()`: Initiate fraud investigation
- `analyze_fraud_network()`: Analyze account connections
- `find_fraud_patterns()`: Detect suspicious patterns
- `get_investigation()`: Retrieve investigation details

## Configuration

Configuration is managed through environment variables and the `AerospikeAgentConfig` class:

### Aerospike Configuration
```bash
AEROSPIKE_HOST=localhost
AEROSPIKE_PORT=3000
AEROSPIKE_TIMEOUT=1000
```

### Graph Service Configuration
```bash
GRAPH_SERVICE_HOST=localhost
GRAPH_SERVICE_PORT=8182
```

### Synchtron Configuration
```bash
SYNCHTRON_COORDINATOR=http://localhost:5000
AGENT_POOL_SIZE=10
TASK_QUEUE_SIZE=1000
HEARTBEAT_INTERVAL=30
ENABLE_TELEMETRY=true
```

### Agent-Specific Configuration
```bash
# Fraud Agent
FRAUD_AGENT_ID=fraud_agent_1
FRAUD_BATCH_SIZE=100
FRAUD_CHECK_INTERVAL=60
FRAUD_RISK_THRESHOLD=70

# Transaction Agent
TRANSACTION_AGENT_ID=transaction_agent_1
TRANSACTION_BATCH_SIZE=500
VALIDATION_STRICT=true

# Investigation Agent
INVESTIGATION_AGENT_ID=investigation_agent_1
INVESTIGATION_MAX_DEPTH=3
INVESTIGATION_TIMEOUT=300
```

## Usage

### Basic Usage

```python
from agents import AerospikeFraudAgent
from agents.config import AerospikeAgentConfig
from synchtron import Context

# Get configuration
config = AerospikeAgentConfig.get_aerospike_config()

# Create agent
agent = AerospikeFraudAgent(
    agent_id="fraud_agent_1",
    aerospike_config=config
)

# Initialize
await agent.initialize()

# Process task
context = Context()
task = {
    "type": "check_transaction",
    "transaction_id": "txn_123"
}

result = await agent.process_task(task, context)

# Cleanup
await agent.cleanup()
```

### Distributed Processing

```python
# Create multiple agents for parallel processing
agents = []
for i in range(3):
    agent = AerospikeFraudAgent(
        agent_id=f"fraud_agent_{i}",
        aerospike_config=config
    )
    await agent.initialize()
    agents.append(agent)

# Distribute work
tasks = []
for agent, chunk in zip(agents, transaction_chunks):
    task = {
        "type": "batch_check",
        "items": chunk
    }
    tasks.append(agent.process_task(task, context))

# Execute concurrently
results = await asyncio.gather(*tasks)
```

### Workflow Orchestration

```python
# Coordinate multiple agents in a workflow
txn_agent = AerospikeTransactionAgent(...)
fraud_agent = AerospikeFraudAgent(...)
inv_agent = AerospikeInvestigationAgent(...)

# Step 1: Create transaction
txn_result = await txn_agent.process_task(create_task, context)

# Step 2: Check for fraud
fraud_result = await fraud_agent.process_task(check_task, context)

# Step 3: Investigate if high risk
if fraud_result["risk_score"] > 70:
    inv_result = await inv_agent.process_task(inv_task, context)
```

## Examples

See `example_usage.py` for comprehensive examples including:
- Single agent operations
- Distributed fraud detection
- Multi-agent workflow orchestration

Run examples:
```bash
python -m agents.example_usage
```

## Integration with Existing Services

The agents can be integrated with existing FastAPI services:

```python
from fastapi import FastAPI
from agents import AerospikeFraudAgent
from agents.config import AerospikeAgentConfig

app = FastAPI()

# Initialize agent at startup
@app.on_event("startup")
async def startup():
    app.state.fraud_agent = AerospikeFraudAgent(
        agent_id="api_fraud_agent",
        aerospike_config=AerospikeAgentConfig.get_aerospike_config()
    )
    await app.state.fraud_agent.initialize()

@app.post("/check-transaction")
async def check_transaction(transaction_id: str):
    task = {
        "type": "check_transaction",
        "transaction_id": transaction_id
    }
    result = await app.state.fraud_agent.process_task(task, Context())
    return result
```

## Dependencies

- `aerospike>=15.0.0`: Aerospike Python client
- `synchtron>=0.1.0`: Synchtron orchestration framework
- `asyncio`: Asynchronous programming support

## Testing

Run tests for the agents:
```bash
pytest backend/tests/test_agents.py
```

## Performance Considerations

- **Connection Pooling**: Each agent maintains its own Aerospike connection
- **Batch Processing**: Use batch operations for better throughput
- **Concurrent Execution**: Multiple agents can process tasks in parallel
- **Resource Cleanup**: Always call `cleanup()` to release resources

## Logging

Agents use Python's logging module. Configure logging level:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Log levels:
- `DEBUG`: Detailed operation logs
- `INFO`: Agent lifecycle and major operations
- `WARNING`: Recoverable errors and missing data
- `ERROR`: Processing errors and failures

## Future Enhancements

- [ ] Add support for agent clustering and failover
- [ ] Implement advanced graph algorithms for pattern detection
- [ ] Add metrics and monitoring integration
- [ ] Support for custom fraud rules via configuration
- [ ] Integration with ML models for risk scoring
- [ ] Real-time streaming fraud detection

## License

Part of the Unified Fraud Detection system - see main LICENSE file.
