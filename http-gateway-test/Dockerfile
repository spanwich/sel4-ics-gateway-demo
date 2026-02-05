FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    bridge-utils \
    iproute2 \
    net-tools \
    iputils-ping \
    procps \
    iptables \
    tcpdump \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY sel4-image/ /sel4-image/

COPY setup-network.sh /usr/local/bin/
COPY start-gateway.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

EXPOSE 443

CMD ["/usr/local/bin/start-gateway.sh"]
