# Stage 1: Build
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev sqlite-dev openssl-dev

WORKDIR /app
COPY Cargo.toml rust-toolchain.toml ./
COPY src/ src/
COPY migrations/ migrations/
COPY contracts/ contracts/

RUN cargo build --release --target=x86_64-unknown-linux-musl

# Stage 2: Minimal runtime
FROM alpine:latest
RUN apk add --no-cache tor sqlite-libs ca-certificates iptables && \
    adduser -D -h /app marketplace && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/tor-marketplace /app/marketplace
COPY scripts/harden.sh /app/harden.sh

RUN chmod +x /app/harden.sh && chown -R marketplace:marketplace /app

USER marketplace

EXPOSE 9080

VOLUME ["/app/data"]

ENTRYPOINT ["/app/marketplace"]
