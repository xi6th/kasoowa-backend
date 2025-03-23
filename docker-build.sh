#!/bin/bash
set -e

echo "Building Docker containers for Kasoowa..."

# Generate a secure JWT secret if not already set
if grep -q "generate_a_secure_secret_key_here" .env; then
  echo "Generating secure JWT secret..."
  JWT_SECRET=$(openssl rand -base64 32)
  sed -i "s/generate_a_secure_secret_key_here/$JWT_SECRET/" .env
  echo "JWT secret generated and updated in .env"
fi

# Make Kafka init script executable
chmod +x kafka-init.sh

# Build and start services
docker-compose build
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Check if services are running
echo "Checking service status:"
docker-compose ps

echo "Setup complete! Your Kasoowa application is now running."
echo ""
echo "Access points:"
echo "- API: http://localhost:8080"
echo "- Kafka UI: http://localhost:8090"
echo "- PgAdmin: http://localhost:5050 (login: admin@kasoowa.com / admin)"
echo ""
echo "To view logs: docker-compose logs -f api"
echo "To stop services: docker-compose down"