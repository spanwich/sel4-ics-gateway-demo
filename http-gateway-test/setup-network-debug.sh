#!/bin/bash
set -e

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "Setting up network for HTTP Gateway (simple TAP mode - debug)..."

# Create tap device directly (no bridge)
ip tuntap add dev tap0 mode tap
ip link set tap0 up

# Assign IP directly to tap0
ip addr add 192.168.1.1/24 dev tap0

# Add static ARP entry for the seL4 gateway (avoid ARP issues)
# MAC address matches QEMU's e1000 setting: 52:54:00:12:34:56
arp -s 192.168.1.10 52:54:00:12:34:56

log "Network setup complete:"
log "  tap0: 192.168.1.1/24"
log "  Static ARP: 192.168.1.10 -> 52:54:00:12:34:56"
log "  Gateway will be at 192.168.1.10:443"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

log "Starting tcpdump on tap0 in background..."
tcpdump -i tap0 -n -l 2>&1 | while read line; do
    echo "[tcpdump] $line"
done &

log "Network ready. Try: ping -c 3 192.168.1.10"
