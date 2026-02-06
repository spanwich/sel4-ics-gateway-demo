#!/bin/bash
# Test with QEMU slirp networking (no TAP, simpler setup)
# This verifies the e1000 driver works before debugging TAP issues
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="http-gateway-base"

# Build base image if needed
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building base image..."
    docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

echo "Running with SLIRP networking (testing e1000 driver)..."
echo "  Port 8443 forwarded to seL4 gateway"
echo "  Test with: curl -k https://localhost:8443/"
echo ""

docker run --rm -it \
    -p 8443:8443 \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME" \
    /usr/local/bin/start-gateway-slirp.sh
