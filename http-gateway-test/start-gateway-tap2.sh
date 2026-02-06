#!/bin/bash
# Let QEMU create and manage the TAP device
set -e

LOG="/tmp/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 HTTP Gateway - TAP v2 (QEMU-managed)..."

IMAGE="/sel4-image/capdl-loader-image-x86_64-pc99"
KERNEL="/sel4-image/kernel-x86_64-pc99"

if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

log "Launching QEMU (QEMU will create/configure tap0)..."

# Let QEMU create the TAP device using our script
# This ensures QEMU has proper ownership of the TAP fd
qemu-system-x86_64 \
  -machine q35 \
  -cpu qemu64,+rdrand,+fsgsbase,+xsave,+xsaveopt \
  -m 512 \
  -nographic \
  -netdev tap,id=net0,script=/usr/local/bin/qemu-ifup.sh,downscript=no \
  -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
  -kernel "$KERNEL" \
  -initrd "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
