#!/bin/bash
set -e

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "Setting up network for HTTP Gateway (bridge mode)..."

# Create bridge
ip link add br0 type bridge
ip link set br0 up

# Create tap device and add to bridge
ip tuntap add dev tap0 mode tap
ip link set tap0 master br0
ip link set tap0 up

# Assign IP to bridge (not tap)
ip addr add 192.168.1.1/24 dev br0

log "Network setup complete:"
log "  br0: 192.168.1.1/24 (bridge)"
log "  tap0: member of br0 (connects to QEMU e1000)"
log "  Gateway will be at 192.168.1.10:443"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# NAT for outbound traffic (if needed)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true

# DNAT: Forward inbound port 443 to seL4 gateway at 192.168.1.10
# This allows: host -> docker:443 -> br0 -> tap0 -> 192.168.1.10:443
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:443

# Allow forwarding between eth0 (Docker network) and br0 (QEMU bridge)
iptables -A FORWARD -i eth0 -o br0 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i br0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

log "DNAT configured: eth0:443 -> 192.168.1.10:443 (via br0/tap0)"
