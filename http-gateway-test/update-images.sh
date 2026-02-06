#!/bin/bash
# Copy latest build images to sel4-image directory
#
# Usage:
#   ./update-images.sh                    # Copy from default build dir
#   ./update-images.sh /path/to/build     # Copy from specified build dir
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-/home/iamfo470/phd/camkes-vm-examples/build-http-gateway-x86}"

if [ ! -d "$BUILD_DIR/images" ]; then
    echo "ERROR: Build directory not found: $BUILD_DIR/images"
    exit 1
fi

echo "Copying images from: $BUILD_DIR/images/"
cp -v "$BUILD_DIR/images/kernel-x86_64-pc99" "$SCRIPT_DIR/sel4-image/"
cp -v "$BUILD_DIR/images/capdl-loader-image-x86_64-pc99" "$SCRIPT_DIR/sel4-image/"

echo ""
echo "Images updated. Run with: ./run-dev.sh"
