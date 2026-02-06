#!/bin/bash
# Debug run script with tcpdump and simple TAP networking
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="http-gateway-base"

# Build base image if needed
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building base image..."
    docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

echo "Running in DEBUG mode with tcpdump..."
echo "  Images from: $SCRIPT_DIR/sel4-image/"

docker run --rm -it \
    --privileged \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun \
    -p 8443:443 \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME" \
    /usr/local/bin/start-gateway-debug.sh
