# Stage 1: Builder
FROM rust:latest AS builder
WORKDIR /usr/src/app

COPY Cargo.toml ./
COPY src ./src/

# Build the release binary
RUN cargo build --release

# Stage 2: Runner
FROM debian:bookworm-slim
WORKDIR /app

# Ensure SSL certificates are available for reqwest outbound calls
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/scanner-core .

EXPOSE 3000
CMD ["./scanner-core"]
