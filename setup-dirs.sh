#!/bin/bash

# Create directory structure
mkdir -p nginx/conf.d
mkdir -p certbot/conf certbot/www

# Create Nginx configuration files
cat > nginx/conf.d/default.conf << 'EOL'
server {
    listen 80;
    listen [::]:80;
    server_name localhost;
    server_tokens off;

    # API endpoints
    location /api/ {
        proxy_pass http://api:8080/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Kafka UI
    location /kafka/ {
        proxy_pass http://kafka-ui:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # PgAdmin
    location /pgadmin/ {
        proxy_pass http://pgadmin:80/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Script-Name /pgadmin;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Grafana
    location /grafana/ {
        proxy_pass http://grafana:3000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Prometheus
    location /prometheus/ {
        proxy_pass http://prometheus:9090/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check
    location /health {
        return 200 'OK';
        add_header Content-Type text/plain;
    }
}
EOL

cat > nginx/conf.d/custom.conf << 'EOL'
# Custom Nginx settings
# This file augments the default Nginx configuration

# gzip settings
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

# Buffer size for POST submissions
client_body_buffer_size 10K;
client_header_buffer_size 1k;

# Max request body size
client_max_body_size 10m;

# Security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
EOL

# Make the Kafka initialization script executable
if [ -f "kafka-init.sh" ]; then
    chmod +x kafka-init.sh
else
    cat > kafka-init.sh << 'EOL'
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
EOL
    chmod +x kafka-init.sh
fi

# Create Prometheus configuration if it doesn't exist
if [ ! -f "prometheus.yml" ]; then
    cat > prometheus.yml << 'EOL'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          # - alertmanager:9093

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'kasoowa-api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/api/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'kafka'
    static_configs:
      - targets: ['kafka:9092']
EOL
fi

echo "Directory structure and configuration files set up successfully."