# Snort IDS Gateway - Vulnerable version for CVE-2022-20685 demonstration
# This container runs Snort 2.9.18 which has the Modbus preprocessor integer overflow
#
# For defensive security research only.

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    libdnet-dev \
    bison \
    flex \
    zlib1g-dev \
    liblzma-dev \
    openssl \
    libssl-dev \
    libnghttp2-dev \
    libluajit-5.1-dev \
    pkg-config \
    wget \
    iptables \
    iproute2 \
    net-tools \
    tcpdump \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

# Create snort user and directories
RUN groupadd snort && \
    useradd -r -g snort snort && \
    mkdir -p /etc/snort/rules \
             /etc/snort/preproc_rules \
             /var/log/snort \
             /usr/local/lib/snort_dynamicrules && \
    touch /etc/snort/rules/white_list.rules \
          /etc/snort/rules/black_list.rules

# Download and build DAQ 2.0.7 (required for Snort 2.9.x)
WORKDIR /tmp
RUN wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz && \
    tar xzf daq-2.0.7.tar.gz && \
    cd daq-2.0.7 && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Download and build Snort 2.9.18 (VULNERABLE to CVE-2022-20685)
# This version has the integer overflow in the Modbus preprocessor
RUN wget https://www.snort.org/downloads/archive/snort/snort-2.9.18.tar.gz && \
    tar xzf snort-2.9.18.tar.gz && \
    cd snort-2.9.18 && \
    ./configure --enable-sourcefire \
                --enable-gre \
                --enable-mpls \
                --enable-targetbased \
                --enable-decoder-preprocessor-rules \
                --enable-ppm \
                --enable-perfprofiling \
                --enable-react \
                --enable-flexresp3 && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Clean up build files
RUN rm -rf /tmp/*

# Copy configuration files
COPY snort.conf /etc/snort/snort.conf
COPY rules/modbus.rules /etc/snort/rules/modbus.rules
COPY rules/local.rules /etc/snort/rules/local.rules
COPY start-snort.sh /usr/local/bin/
COPY setup-network.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/*.sh && \
    chown -R snort:snort /var/log/snort

EXPOSE 502

CMD ["/usr/local/bin/start-snort.sh"]
