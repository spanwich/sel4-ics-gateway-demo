#!/bin/bash
set -e

LOG="/logs/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 ICS Gateway..."

# Setup network first
/usr/local/bin/setup-network.sh

# Check for seL4 image
IMAGE="/sel4-image/capdl-loader-image-arm-qemu-arm-virt"
if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

log "Launching QEMU with seL4..."
log "  net0 (tap0): 192.168.96.2 (untrusted)"
log "  net1 (tap1): 192.168.95.1 (protected)"

# Run QEMU, timestamp all output
qemu-system-arm \
  -machine virt,virtualization=on,highmem=off,secure=off \
  -cpu cortex-a15 \
  -nographic \
  -m size=1024 \
  -global virtio-mmio.force-legacy=false \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
  -netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
  -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57 \
  -kernel "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
