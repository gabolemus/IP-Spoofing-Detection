FROM rust:latest as builder

WORKDIR /usr/src/traffic-monitor
COPY . .

RUN cargo install --path .
ENV CARGO_HOME=/usr/local/cargo

FROM debian:bullseye-slim as runner

RUN apt-get -qy update && apt-get -qy install \
    tshark \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/traffic-monitor /usr/local/bin/traffic-monitor

RUN mkdir /traffic-analysis

VOLUME [ "/traffic-analysis" ]

ENTRYPOINT [ "traffic-monitor" ]

ENV PCAP_FILE /traffic-analysis/traffic.pcap

CMD [ "traffic-monitor" ]
