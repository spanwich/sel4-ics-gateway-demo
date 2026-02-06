#!/bin/bash
# Test with QEMU user-mode networking (slirp) to verify e1000 driver works
set -e

LOG="/tmp/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 HTTP Gateway - SLIRP MODE (testing e1000 driver)..."

IMAGE="/sel4-image/capdl-loader-image-x86_64-pc99"
KERNEL="/sel4-image/kernel-x86_64-pc99"

if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

log "Using QEMU user-mode networking (slirp)"
log "  Host port 8443 -> Guest 192.168.1.10:443"
log "  QEMU will act as gateway for the guest"

# QEMU with slirp networking
# This tests if the e1000 driver works without TAP complications
qemu-system-x86_64 \
  -machine q35 \
  -cpu qemu64,+rdrand,+fsgsbase,+xsave,+xsaveopt \
  -m 512 \
  -nographic \
  -netdev user,id=net0,net=192.168.1.0/24,host=192.168.1.1,hostfwd=tcp::8443-192.168.1.10:443 \
  -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
  -kernel "$KERNEL" \
  -initrd "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
