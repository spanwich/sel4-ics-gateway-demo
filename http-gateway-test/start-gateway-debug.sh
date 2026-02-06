#!/bin/bash
set -e

LOG="/tmp/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 HTTP Gateway (x86_64) - DEBUG MODE..."

# Setup network (debug version with tcpdump)
chmod +x /usr/local/bin/setup-network-debug.sh
/usr/local/bin/setup-network-debug.sh

IMAGE="/sel4-image/capdl-loader-image-x86_64-pc99"
KERNEL="/sel4-image/kernel-x86_64-pc99"

# Check for seL4 image
if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

log "Launching QEMU with seL4..."
log "  tap0: 192.168.1.1 (host) <-> 192.168.1.10 (gateway)"

# QEMU options for x86_64
QEMU_OPTS="-machine q35"
QEMU_OPTS="$QEMU_OPTS -cpu qemu64,+rdrand,+fsgsbase,+xsave,+xsaveopt"
QEMU_OPTS="$QEMU_OPTS -m 512"
QEMU_OPTS="$QEMU_OPTS -nographic"

# Start QEMU in background
qemu-system-x86_64 \
  $QEMU_OPTS \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
  -kernel "$KERNEL" \
  -initrd "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done &

QEMU_PID=$!

# Wait for seL4 to boot
log "Waiting 5 seconds for seL4 to boot..."
sleep 5

# Test ping
log "Testing ping to 192.168.1.10..."
ping -c 3 192.168.1.10 || log "Ping failed (expected if gateway hasn't replied yet)"

# Keep running
log "QEMU running (PID: $QEMU_PID). Press Ctrl+C to stop."
wait $QEMU_PID
