#!/bin/bash
# Run with QEMU-managed TAP (QEMU creates the TAP device)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="http-gateway-base"

# Build base image if needed (force rebuild to include new scripts)
echo "Building base image..."
docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"

echo "Running with QEMU-managed TAP..."
echo "  QEMU will create tap0 and configure it"
echo "  Test with: ping 192.168.1.10 (from another terminal in container)"
echo ""

docker run --rm -it \
    --privileged \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun \
    -p 8443:443 \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME" \
    /usr/local/bin/start-gateway-tap2.sh
