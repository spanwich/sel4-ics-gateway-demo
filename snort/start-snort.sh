#!/bin/bash
# Start script for Snort IDS Gateway - NFQUEUE Inline Mode
# Runs Snort 2.9.18 (VULNERABLE to CVE-2022-20685) as true inline IPS
#
# NFQUEUE mode means:
# - iptables sends packets to kernel queue
# - Snort receives packets, inspects them, returns ACCEPT/DROP
# - If Snort hangs (CVE-2022-20685), packets stay in queue = traffic stops!
#
# For defensive security research demonstration.

set -e

LOG="/logs/snort-gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "=============================================="
log "  Snort IDS Gateway - NFQUEUE Inline Mode"
log "  Version: 2.9.18 (CVE-2022-20685 present)"
log "=============================================="

# Setup network (creates NFQUEUE rules)
log "Setting up network..."
/usr/local/bin/setup-network.sh

# Wait for network to stabilize
sleep 2

# Create directories
mkdir -p /var/run/snort /var/log/snort

# Check DAQ modules available
log ""
log "Checking DAQ modules..."
snort --daq-list 2>&1 | tee -a "$LOG"

# Verify nfq module is available
if ! snort --daq-list 2>&1 | grep -q "nfq"; then
    log "ERROR: nfq DAQ module not available!"
    log "Cannot run in inline mode. Falling back to passive mode."

    # Fallback: remove NFQUEUE rules, use simple forwarding
    iptables -F FORWARD
    iptables -A FORWARD -j ACCEPT

    UNTRUSTED_IF=$(cat /tmp/untrusted_if 2>/dev/null || echo "eth0")
    exec snort -c /etc/snort/snort.conf \
        -i $UNTRUSTED_IF \
        -A console \
        -l /var/log/snort \
        --daq pcap \
        --daq-mode passive \
        -k none
fi

log ""
log "╔════════════════════════════════════════════════════════════════╗"
log "║  Starting Snort in NFQUEUE Inline Mode                         ║"
log "╠════════════════════════════════════════════════════════════════╣"
log "║                                                                ║"
log "║  Modbus preprocessor ENABLED (vulnerable to CVE-2022-20685)    ║"
log "║                                                                ║"
log "║  Attack this container with:                                   ║"
log "║    ./cve_tools/cve_20685_attack 127.0.0.1 503                  ║"
log "║                                                                ║"
log "║  Expected result:                                              ║"
log "║    • Snort enters infinite loop in Modbus preprocessor         ║"
log "║    • NFQUEUE stops receiving verdicts                          ║"
log "║    • ALL Modbus traffic to PLC stops completely                ║"
log "║    • Snort CPU goes to 100%                                    ║"
log "║                                                                ║"
log "║  Verify with:                                                  ║"
log "║    modscan -t 127.0.0.1 -p 503  (before: works, after: hangs)  ║"
log "║    docker exec ics-snort top     (should show 100% CPU)        ║"
log "║                                                                ║"
log "╚════════════════════════════════════════════════════════════════╝"
log ""

# Start Snort with NFQUEUE DAQ
# -Q enables inline mode (required for nfq)
# --daq nfq uses the netfilter queue module
# --daq-var queue=0 specifies queue number (matches iptables NFQUEUE rule)
exec snort -c /etc/snort/snort.conf \
    -Q \
    -A console \
    -l /var/log/snort \
    --daq nfq \
    --daq-var queue=0 \
    -k none
