#!/bin/bash

echo "Starting hot-reload monitoring..."

# Check if diesel is in PATH
echo "Checking diesel installation..."
which diesel || echo "WARNING: diesel command not found in PATH"

# Wait for database
echo "Waiting for database..."
until pg_isready -h db -p 5432 -U postgres; do
  echo "Database not ready yet - sleeping for 2 seconds..."
  sleep 2
done
echo "Database is ready!"

# Ensure diesel is in PATH
export PATH="/root/.cargo/bin:${PATH}"

# Run migrations
echo "Running diesel setup..."
diesel setup || echo "WARNING: diesel setup failed"

echo "Running diesel migrations..."
diesel migration run || echo "WARNING: diesel migration failed"

# Create schema.rs file with proper table definitions if needed
if [ ! -f src/schema.rs ]; then
  echo "Creating schema.rs file..."
  diesel print-schema > src/schema.rs || echo "WARNING: Could not generate schema.rs automatically"
fi

# Create directory for logs
mkdir -p /app/logs
touch /app/logs/api_server.log

# Initial build with detailed error reporting
echo "Building application..."
RUST_BACKTRACE=1 cargo build || {
  echo "ERROR: Build failed. Detailed error output:"
  echo "----------------------------------------"
  cat target/debug/build/*/stderr || echo "No stderr output available"
  echo "----------------------------------------"
  echo "WARNING: cargo build failed"
}

# Start file watching
echo "Watching for file changes..."
while true; do
  inotifywait -r -e modify,create,delete,move ./src ./Cargo.toml
  echo "Change detected! Rebuilding..."
  
  # Clean target if needed (uncomment if you experience weird build errors)
  # cargo clean
  
  # Build with full error output
  RUST_BACKTRACE=1 cargo build || {
    echo "ERROR: Build failed. Detailed error output:"
    echo "----------------------------------------"
    cat target/debug/build/*/stderr || echo "No stderr output available"
    echo "----------------------------------------"
    echo "WARNING: cargo build failed"
    continue
  }
  
  # Only run if build succeeds
  echo "Build successful, running application..."
  cargo run || echo "WARNING: Application execution failed"
done