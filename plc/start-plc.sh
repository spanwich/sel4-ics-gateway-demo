#!/bin/bash
#
# FrostyGoop District Heating Simulation
# Startup script
#

set -e

LOG_FILE="${LOG_FILE:-/logs/plc.log}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log startup
{
    echo "========================================"
    echo "FrostyGoop District Heating Simulation"
    echo "Starting at $(date)"
    echo "libmodbus 3.1.2 (VULNERABLE)"
    echo "========================================"
} | tee -a "$LOG_FILE"

# Execute the controller
exec /src/heating_controller
