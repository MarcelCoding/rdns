FROM rust:latest AS builder
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

ENV USER=rdns
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /rdns
COPY Cargo.toml Cargo.lock ./

RUN mkdir src \
 && echo "fn main() { println!(\"Docker placeholder main.rs\"); }" > src/main.rs \
 && cargo build --release \
 && rm -rf target/release/deps/rdns*

COPY src ./src

RUN cargo build --release

FROM debian
#gcr.io/distroless/cc

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /rdns
COPY --from=builder /rdns/target/release/rdns ./rdns

USER rdns:rdns

ENTRYPOINT ["/rdns/rdns"]
