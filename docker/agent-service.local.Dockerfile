# AUTO-DERIVED from Agent-mongo-fraud-agents/src/Synktron.AgentFramework.Python.Service/Dockerfile
# — that Dockerfile's COPY lines hardcode "Agent/src/..." (assumes the checkout is literally
# named "Agent", matching Build-AgentPackages.ps1's own comment on this exact issue), but this
# repo's sibling checkout is Agent-mongo-fraud-agents. Regenerate after any change to the real
# Dockerfile with:
#   sed 's#Agent/src/#Agent-mongo-fraud-agents/src/#g' \
#     ../Agent-mongo-fraud-agents/src/Synktron.AgentFramework.Python.Service/Dockerfile \
#     > docker/agent-service.local.Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install service dependencies
COPY Agent-mongo-fraud-agents/src/Synktron.AgentFramework.Python.Service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Map .NET-style flat dot-named folders into Python nested package structure
COPY Agent-mongo-fraud-agents/src/Synktron.AgentFramework.Python.Agents/ ./src/Synktron/AgentFramework/Python/Agents/
COPY Agent-mongo-fraud-agents/src/Synktron.AgentFramework.Python.Service/ ./src/Synktron/AgentFramework/Python/Service/

# Create namespace __init__.py files for intermediate package levels
RUN touch ./src/Synktron/__init__.py \
    ./src/Synktron/AgentFramework/__init__.py \
    ./src/Synktron/AgentFramework/Python/__init__.py

# /app/src                              — Synktron.AgentFramework.Python namespace
# /app/src/Synktron/AgentFramework/Python/Agents — aerospike_client + fraud_nodes as top-level imports
ENV PYTHONPATH=/app/src:/app/src/Synktron/AgentFramework/Python/Agents

EXPOSE 8000
# Shell form (not exec-form array) so ${SERVICE_PORT:-8000} actually expands -- Mesh's
# ContainerRuntime:Port convention is 9090 for AWS ECS ContainerInstance deployments (confirmed
# live against a real Mesh instance), set via the registration's Configuration/SERVICE_PORT.
# Defaults to 8000 (matching EXPOSE) for local/compose use where nothing sets it.
CMD uvicorn Synktron.AgentFramework.Python.Service.main:app --host 0.0.0.0 --port ${SERVICE_PORT:-8000}
