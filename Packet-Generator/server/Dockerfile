FROM rust:latest as builder

WORKDIR /usr/src/packet-generator
COPY . .

RUN cargo install --path .
ENV CARGO_HOME=/usr/local/cargo

FROM debian:buster-slim as runner

COPY --from=builder /usr/local/cargo/bin/packet-generator /usr/local/bin/packet-generator

CMD ["packet-generator"]
