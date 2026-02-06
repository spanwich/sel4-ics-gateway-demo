#!/bin/bash
# QEMU TAP interface up script
# Called by QEMU when it creates the TAP device

IFACE=$1
echo "[qemu-ifup] Configuring $IFACE..."

ip link set $IFACE up
ip addr add 192.168.1.1/24 dev $IFACE

# Add static ARP for the seL4 gateway
arp -s 192.168.1.10 52:54:00:12:34:56

echo "[qemu-ifup] $IFACE ready: 192.168.1.1/24"
