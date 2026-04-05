FROM rust:1.86-bookworm AS builder

WORKDIR /build
COPY Cargo.toml ./
COPY src src/
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /build/target/release/stellarae_twofa /app/stellarae_twofa
RUN mkdir -p /app/data

EXPOSE 4100

ENV TWOFA_HOST=0.0.0.0
ENV TWOFA_PORT=4100
ENV DATABASE_URL=sqlite:/app/data/twofa.sqlite
ENV SERVICE_ID=twofa-container
ENV LOG_LEVEL=info

ENTRYPOINT ["/app/stellarae_twofa"]
