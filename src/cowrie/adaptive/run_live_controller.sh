#!/bin/bash
# Script to run live_adaptive_controller.py using the correct virtual environment

# Define paths
VENV_PYTHON="/home/dhikshanya06/cowrie/cowrie-env/bin/python3"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CONTROLLER_SCRIPT="$SCRIPT_DIR/live_adaptive_controller.py"

# Check if venv python exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: Virtual environment python not found at $VENV_PYTHON"
    exit 1
fi

# Run the controller
echo "[*] Launching Live Adaptive Controller using cowrie-env..."
exec "$VENV_PYTHON" "$CONTROLLER_SCRIPT" "$@"
