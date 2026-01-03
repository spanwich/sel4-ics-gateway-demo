#!/bin/bash
# Start script for Snort IDS Gateway
# Runs Snort 2.9.18 (VULNERABLE to CVE-2022-20685) in inline/IPS mode
#
# For defensive security research demonstration.

set -e

LOG="/logs/snort-gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "=============================================="
log "  Snort IDS Gateway (VULNERABLE)"
log "  Version: 2.9.18 (CVE-2022-20685 present)"
log "=============================================="

# Setup network
log "Setting up network..."
/usr/local/bin/setup-network.sh

# Wait for network to stabilize
sleep 2

# Detect interfaces
ETH0_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
ETH1_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")

if [[ "$ETH0_IP" == 192.168.96.* ]]; then
    UNTRUSTED_ETH="eth0"
    PROTECTED_ETH="eth1"
elif [[ "$ETH1_IP" == 192.168.96.* ]]; then
    UNTRUSTED_ETH="eth1"
    PROTECTED_ETH="eth0"
else
    log "WARNING: Cannot determine dual-network setup, using eth0 for both"
    UNTRUSTED_ETH="eth0"
    PROTECTED_ETH="eth0"
fi

log "Interfaces: untrusted=$UNTRUSTED_ETH, protected=$PROTECTED_ETH"

# Create pid directory
mkdir -p /var/run/snort

# Check if Snort can run inline (requires afpacket DAQ)
log "Checking DAQ modules..."
snort --daq-list 2>&1 | head -20 | tee -a "$LOG"

log ""
log "Starting Snort in IDS mode (packet inspection)..."
log "Modbus preprocessor ENABLED (vulnerable to CVE-2022-20685)"
log ""
log "Attack this container with:"
log "  ./cve_tools/cve_20685_attack 127.0.0.1 503"
log ""
log "This will trigger an infinite loop in the Modbus preprocessor,"
log "causing Snort to stop processing packets (IDS blindness)."
log ""

# Try inline mode first, fall back to IDS mode
if snort --daq-list 2>&1 | grep -q "afpacket"; then
    log "Starting Snort in INLINE mode (IPS)..."

    # Configure afpacket inline bridge
    # Note: In Docker, we use iptables forwarding instead of true inline bridging
    exec snort -c /etc/snort/snort.conf \
        -i $UNTRUSTED_ETH \
        -A console \
        -q \
        -l /var/log/snort \
        --daq pcap \
        --daq-mode passive \
        -k none
else
    log "afpacket not available, starting in passive IDS mode..."
    exec snort -c /etc/snort/snort.conf \
        -i $UNTRUSTED_ETH \
        -A console \
        -q \
        -l /var/log/snort \
        -k none
fi
