#!/bin/bash
set -e

LOG="/tmp/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 HTTP Gateway (x86_64)..."

# Setup network first
/usr/local/bin/setup-network.sh

IMAGE="/sel4-image/capdl-loader-image-x86_64-pc99"
KERNEL="/sel4-image/kernel-x86_64-pc99"

# Check for seL4 image
if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

log "Launching QEMU with seL4..."
log "  tap0: 192.168.1.1 (host) <-> 192.168.1.10 (gateway)"
log "  Gateway HTTPS on :443"

# QEMU options for x86_64
QEMU_OPTS="-machine q35"
QEMU_OPTS="$QEMU_OPTS -cpu qemu64,+rdrand,+fsgsbase,+xsave,+xsaveopt"
QEMU_OPTS="$QEMU_OPTS -m 512"
QEMU_OPTS="$QEMU_OPTS -nographic"

# Enable KVM if available
if [ -c /dev/kvm ] && [ -w /dev/kvm ]; then
    log "KVM acceleration enabled"
    QEMU_OPTS="$QEMU_OPTS -enable-kvm -cpu host"
fi

# Run QEMU with TAP networking
# NOTE: Using e1000 (82540EM) with standalone driver - uses legacy INTx interrupts
# by default, avoiding MSI-X issues that plagued e1000e (82574L) with seL4.
qemu-system-x86_64 \
  $QEMU_OPTS \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
  -kernel "$KERNEL" \
  -initrd "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
