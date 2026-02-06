#!/bin/bash
# Development run script - mounts sel4-image as volume (no rebuild needed)
#
# Usage:
#   ./run-dev.sh              # Run with current images
#   ./run-dev.sh --build-base # Rebuild base image first
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="http-gateway-base"

# Build base image if requested or doesn't exist
if [[ "$1" == "--build-base" ]] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building base image (one-time)..."
    docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

echo "Running with volume-mounted sel4-image..."
echo "  Images from: $SCRIPT_DIR/sel4-image/"

docker run --rm -it \
    --privileged \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun \
    -p 8443:443 \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME"
