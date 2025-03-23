FROM rust:1.81 AS builder

WORKDIR /usr/src/kasoowa

# Install dependencies for compilation with OpenSSL 3 and cmake for rdkafka
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    librdkafka-dev \
    libpq-dev \
    build-essential \
    perl \
    perl-base \
    perl-modules \
    openssl \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for OpenSSL
ENV OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
ENV OPENSSL_INCLUDE_DIR=/usr/include/openssl

# Copy all source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies (using OpenSSL 3)
RUN apt-get update && apt-get install -y \
    libssl3 \
    librdkafka1 \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/kasoowa/target/release/kasoowa .

# Create a non-root user
RUN useradd -m kasoowa
USER kasoowa

# Set environment variables
ENV RUST_LOG=info
ENV HOST=0.0.0.0
ENV PORT=8080

# Expose the application port
EXPOSE 8080

# Run the binary
CMD ["./kasoowa"]