FROM rustlang/rust:stable AS chef

RUN update-ca-certificates

RUN cargo install cargo-chef
WORKDIR /rdns

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

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

COPY --from=planner /rdns/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /rdns

COPY --from=builder /rdns/target/release/rdns ./rdns

USER rdns:rdns

ENTRYPOINT ["/rdns/rdns"]
