#!/bin/bash
# Network setup for Snort IDS Gateway
# Configures packet forwarding mode (NOT protocol break)
#
# For defensive security research demonstration.

set -e

LOG="/logs/snort-gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Setting up Snort gateway network (packet-forwarding mode)..."

# Get IPs from interfaces
ETH0_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1 || echo "")
ETH1_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1 || echo "")

log "Detected: eth0=$ETH0_IP, eth1=$ETH1_IP"

# Determine which eth is untrusted (96.x) vs protected (95.x)
if [[ "$ETH0_IP" == 192.168.96.* ]]; then
    UNTRUSTED_ETH="eth0"
    PROTECTED_ETH="eth1"
elif [[ "$ETH1_IP" == 192.168.96.* ]]; then
    UNTRUSTED_ETH="eth1"
    PROTECTED_ETH="eth0"
else
    log "ERROR: Cannot determine network assignment. Expected 192.168.96.x on one interface."
    log "Trying single-interface mode..."
    UNTRUSTED_ETH="eth0"
    PROTECTED_ETH="eth0"
fi

log "Network detection: $UNTRUSTED_ETH=untrusted, $PROTECTED_ETH=protected"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
log "IP forwarding enabled"

# Disable reverse path filtering (required for asymmetric routing)
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$UNTRUSTED_ETH/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$PROTECTED_ETH/rp_filter

# Configure iptables for DNAT (packet forwarding mode)
# This is fundamentally different from seL4's protocol-break architecture:
# - Same TCP connection flows through from client to PLC
# - Snort inspects but does not terminate the connection
# - Attacker can manipulate TCP state end-to-end

# DNAT: Redirect incoming port 502 to PLC
iptables -t nat -A PREROUTING -p tcp --dport 502 -j DNAT --to-destination 192.168.95.2:502

# SNAT: Masquerade outgoing traffic so PLC can respond
iptables -t nat -A POSTROUTING -o $PROTECTED_ETH -j MASQUERADE

# Forward rules
iptables -A FORWARD -i $UNTRUSTED_ETH -o $PROTECTED_ETH -p tcp --dport 502 -j ACCEPT
iptables -A FORWARD -i $PROTECTED_ETH -o $UNTRUSTED_ETH -p tcp --sport 502 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

log "iptables configured for packet-forwarding mode"
log ""
log "=== PACKET FORWARDING ARCHITECTURE ==="
log "Client ──TCP──> Snort ──TCP──> PLC"
log "         (same connection flows through)"
log ""
log "Limitations vs Protocol Break:"
log "  - Client can influence PLC's TCP state"
log "  - Timing attacks possible"
log "  - TCP segmentation evasion possible"
log "  - Malformed TCP options may reach PLC"
log "======================================="
