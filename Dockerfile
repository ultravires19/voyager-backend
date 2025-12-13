# ============================================
# Fantastic Voyagers - Auth Service Dockerfile
# ============================================
# Production build for Hetzner CPX21 deployment

# ============================================
# Stage 1: Build
# ============================================
FROM rust:1.90-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main to build dependencies (caching layer)
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY . .

# Build the real application
RUN touch src/main.rs && \
    cargo build --release

# ============================================
# Stage 2: Runtime
# ============================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 voyagers

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/voyager-backend /app/voyager-backend

# Change ownership
RUN chown -R voyagers:voyagers /app

# Switch to non-root user
USER voyagers

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["/app/voyager-backend"]
