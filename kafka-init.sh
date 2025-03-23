#!/bin/bash
set -e

# Wait for Kafka to be ready
echo "Waiting for Kafka to be ready..."
cub kafka-ready -b kafka:9092 1 30

# Create topics
echo "Creating Kafka topics..."
kafka-topics --create --if-not-exists --bootstrap-server kafka:9092 --partitions 3 --replication-factor 1 --topic user-events
kafka-topics --create --if-not-exists --bootstrap-server kafka:9092 --partitions 3 --replication-factor 1 --topic auth-events
kafka-topics --create --if-not-exists --bootstrap-server kafka:9092 --partitions 3 --replication-factor 1 --topic vendor-events
kafka-topics --create --if-not-exists --bootstrap-server kafka:9092 --partitions 3 --replication-factor 1 --topic affiliate-events

# List created topics
echo "Listing topics:"
kafka-topics --list --bootstrap-server kafka:9092

echo "Kafka initialization completed."