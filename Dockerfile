FROM rust:1.87-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release --bin vyrnd --bin vyrn --bin vyrn-http

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home vyrn \
    && mkdir -p /var/lib/vyrn /run/vyrn \
    && chown vyrn:vyrn /var/lib/vyrn /run/vyrn
COPY --from=builder /src/target/release/vyrnd /usr/local/bin/vyrnd
COPY --from=builder /src/target/release/vyrn /usr/local/bin/vyrn
COPY --from=builder /src/target/release/vyrn-http /usr/local/bin/vyrn-http
RUN printf '#!/bin/sh\nexec curl --fail --silent http://127.0.0.1:7433/health/ready >/dev/null\n' > /usr/local/bin/vyrn-healthcheck \
    && chmod 755 /usr/local/bin/vyrn-healthcheck
USER vyrn
VOLUME ["/var/lib/vyrn"]
EXPOSE 7432 7433
ENV VYRN_BIND=0.0.0.0:7432 \
    VYRN_ADMIN_BIND=0.0.0.0:7433 \
    VYRN_DATA=/var/lib/vyrn \
    VYRN_USERNAME=vyrn \
    VYRN_DATABASE=default \
    VYRN_PASSWORD_HASH_FILE=/run/secrets/vyrn_password_hash \
    VYRN_TLS_CERT_FILE=/run/secrets/vyrn_tls_cert \
    VYRN_TLS_KEY_FILE=/run/secrets/vyrn_tls_key
ENTRYPOINT ["vyrnd"]
