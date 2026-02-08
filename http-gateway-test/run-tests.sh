#!/bin/bash
#
# run-tests.sh — Automated HTTP endpoint tests for seL4 HTTP Gateway
#
# Launches QEMU in Docker (SLIRP networking), waits for boot,
# runs 5 endpoint tests, reports results, and cleans up.
#
# Usage:
#   ./run-tests.sh                              # Use existing images
#   ./run-tests.sh /path/to/build-http-gw-cp    # Copy images first
#
# Requires: docker, curl
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="http-gw-autotest"
IMAGE_NAME="http-gateway-base"
BOOT_TIMEOUT=60
PORT=8443

# --- Cleanup ---
cleanup() {
    if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "Stopping container..."
        docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- Copy images if build path provided ---
if [ $# -ge 1 ]; then
    BUILD_DIR="$1"
    echo "Copying images from $BUILD_DIR..."
    "$SCRIPT_DIR/update-images.sh" "$BUILD_DIR"
    echo ""
fi

# --- Verify images ---
for img in kernel-x86_64-pc99 capdl-loader-image-x86_64-pc99; do
    if [ ! -f "$SCRIPT_DIR/sel4-image/$img" ]; then
        echo "FATAL: Image not found: $SCRIPT_DIR/sel4-image/$img"
        exit 1
    fi
done

# --- Build Docker base image if needed ---
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building Docker base image..."
    docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

# --- Stop any previous container ---
if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Stopping previous container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    sleep 1
fi

# --- Check port availability ---
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    echo "FATAL: Port $PORT is already in use"
    ss -tlnp | grep ":${PORT} "
    exit 1
fi

# --- Launch QEMU in Docker ---
echo "=== Launching QEMU in Docker (SLIRP) ==="
docker run --rm -d \
    --name "$CONTAINER_NAME" \
    -p "${PORT}:${PORT}" \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME" \
    /usr/local/bin/start-gateway-slirp.sh >/dev/null

echo "Container: $CONTAINER_NAME"
echo "Waiting for boot (timeout: ${BOOT_TIMEOUT}s)..."

# --- Wait for boot ---
ELAPSED=0
READY=false
while [ $ELAPSED -lt $BOOT_TIMEOUT ]; do
    if docker logs "$CONTAINER_NAME" 2>/dev/null | grep -q "\[ControlPlane\] Ready:"; then
        READY=true
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if ! $READY; then
    echo "FATAL: Boot timeout after ${BOOT_TIMEOUT}s"
    echo "--- Container logs (last 30 lines) ---"
    docker logs --tail 30 "$CONTAINER_NAME" 2>/dev/null || echo "(no logs)"
    exit 1
fi

echo "Boot complete in ${ELAPSED}s"
sleep 3  # Let lwIP + TLS listener finish setup
echo ""

# --- HTTP Endpoint Tests ---
PASS=0
FAIL=0
TOTAL=5

run_test() {
    local test_num="$1"
    local description="$2"
    local expected_code="$3"
    shift 3

    local actual_code
    actual_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 15 --max-time 30 "$@" 2>/dev/null) || actual_code="000"

    if [ "$actual_code" = "$expected_code" ]; then
        echo "  PASS [$test_num] $description (HTTP $actual_code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$test_num] $description (expected $expected_code, got $actual_code)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Running HTTP Endpoint Tests ==="

# Test 1: Unauthenticated status -> 403
run_test 1 "GET /api/status (unauthenticated)" "403" \
    "https://localhost:${PORT}/api/status"

# Test 2: Admin login -> 200
run_test 2 "POST /api/login (admin)" "200" \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login"

# Test 3: Authenticated status -> 200
run_test 3 "GET /api/status (authenticated)" "200" \
    "https://localhost:${PORT}/api/status"

# Test 4: Logout -> 200
run_test 4 "POST /api/logout" "200" \
    -X POST "https://localhost:${PORT}/api/logout"

# Test 5: Status after logout -> 403
run_test 5 "GET /api/status (after logout)" "403" \
    "https://localhost:${PORT}/api/status"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "--- Container logs (last 30 lines) ---"
    docker logs --tail 30 "$CONTAINER_NAME" 2>/dev/null || echo "(no logs)"
    exit 1
fi

echo ""
echo "All tests passed."
exit 0
