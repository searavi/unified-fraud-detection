#!/usr/bin/env python3
"""
Drops a MongoDB database entirely. Used by teardown-fraud-detection-aws.ps1 via an ECS
run-task command override (see backend.Dockerfile's COPY of this file) so it executes inside
Mesh's VPC, where the shared Mongo instance's private Cloud Map DNS name is actually reachable —
not from wherever the teardown script's own process happens to run.
"""

import argparse

from pymongo import MongoClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mongo-uri", required=True)
    parser.add_argument("--db-name", required=True)
    args = parser.parse_args()

    client = MongoClient(args.mongo_uri)
    client.drop_database(args.db_name)
    client.close()
    print(f"Dropped database {args.db_name}")


if __name__ == "__main__":
    main()
