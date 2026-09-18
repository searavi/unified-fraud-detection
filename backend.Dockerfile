FROM python:3.12.11-alpine3.22

ENV GRAPH_HOST_ADDRESS="asgraph-service"

RUN mkdir /backend
RUN apk add --no-cache \
    build-base \
    openssl-dev \
    linux-headers \
    zlib-dev \
    yaml-dev
COPY ./backend /backend
RUN mkdir -p /backend/scripts
COPY ./scripts/generate_user_data.py /backend/scripts/generate_user_data.py
# seed_mongo.py / reset_hitl_policy.py: not run by the default CMD below — invoked via a
# container command override (ECS `run-task --overrides`) so AWS's Mongo-seeding/HITL-scrub
# maintenance steps execute genuinely inside the VPC (this image's own task networking), instead
# of from wherever the deploy/teardown script's own process happens to run — which, on a GitHub
# Actions hosted runner, has no route to Mesh's Mongo's private Cloud Map DNS at all.
COPY ./scripts/seed_mongo.py /backend/scripts/seed_mongo.py
COPY ./scripts/reset_hitl_policy.py /backend/scripts/reset_hitl_policy.py
COPY ./scripts/drop_database.py /backend/scripts/drop_database.py
WORKDIR /backend
RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--root-path", "/api", "--port", "4000", "--loop", "asyncio"]