FROM alpine:latest

RUN apk add --update --no-cache tcpdump && \
    rm -rf /var/cache/apk/*

VOLUME [ "/tcpdump" ]

ENTRYPOINT [ "/usr/bin/tcpdump" ]

CMD [ "-C", "1000", "-v", "-i", "any", "-w", "/tcpdump/tcpdump.pcap" ]
