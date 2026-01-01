FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    qemu-system-arm \
    bridge-utils \
    iproute2 \
    net-tools \
    iputils-ping \
    procps \
    iptables \
    tcpdump \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy seL4 image into the container (embedded at build time)
COPY sel4-image/capdl-loader-image-arm-qemu-arm-virt /sel4-image/capdl-loader-image-arm-qemu-arm-virt

COPY setup-network.sh /usr/local/bin/
COPY start-gateway.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

EXPOSE 502

CMD ["/usr/local/bin/start-gateway.sh"]
