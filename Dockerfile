# Builder stage
FROM rust:bookworm as builder

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Create dummy source for dependency caching
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# Build dependencies (release)
RUN cargo build --release

# Remove dummy build artifacts
RUN rm -f target/release/deps/recipe_viewer*

# Copy actual source code
COPY . .

# NOTE: existing recipes.db is required for sqlx compile-time checks
# unless sqlx-data.json is present and SQLX_OFFLINE=true is set.
# Since we don't have sqlx-cli installed to generate json, we copy the db.
ENV DATABASE_URL=sqlite:recipes.db

# Build application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (sqlite3 for db interaction if needed, ca-certificates for ssl)
# Install runtime dependencies including Chromium for headless_chrome
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlite3 \
    chromium \
    fonts-liberation \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/recipe_viewer /usr/local/bin/

# Copy migrations (sqlx migrate! embeds them, but sometimes useful to have)
# Actually, sqlx::migrate!() embeds migration sql in the binary, so we don't strictly need the folder at runtime unless using CLI.
# However, copying templates/ is typically NOT needed for Askama (compiled in) unless we are loading standard HTML templates dynamically.
# Askama embeds templates into binary.

# Expose port
EXPOSE 8080

# Set default env (can be overridden)
ENV DATABASE_URL=sqlite:recipes.db

# Command to run
CMD ["recipe_viewer"]
