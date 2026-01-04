#!/bin/bash
# Demo launcher - Creates tmux session with 4 quadrants
#
# Layout:
# ┌─────────────────┬─────────────────┐
# │   PLC (plc)     │  seL4 Gateway   │
# │   Port 5020     │   Port 502      │
# ├─────────────────┼─────────────────┤
# │  Snort IDS      │  User Terminal  │
# │   Port 503      │   (commands)    │
# └─────────────────┴─────────────────┘
#
# Usage: ./scripts/demo.sh

set -e

SESSION="ics-demo"

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create new session with first pane (PLC)
tmux new-session -d -s "$SESSION" -n "demo"

# Split horizontally (top/bottom)
tmux split-window -v -t "$SESSION"

# Split top pane vertically (left/right)
tmux select-pane -t "$SESSION:0.0"
tmux split-window -h -t "$SESSION"

# Split bottom pane vertically (left/right)
tmux select-pane -t "$SESSION:0.2"
tmux split-window -h -t "$SESSION"

# Now we have 4 panes:
# Pane 0: top-left     (PLC)
# Pane 1: top-right    (Gateway)
# Pane 2: bottom-left  (Snort)
# Pane 3: bottom-right (User terminal)

# Send commands to each pane
# Pane 0: PLC
tmux send-keys -t "$SESSION:0.0" "echo '=== PLC Container (Port 5020) ===' && sudo docker compose up plc" C-m

# Pane 1: seL4 Gateway
tmux send-keys -t "$SESSION:0.1" "echo '=== seL4 Gateway (Port 502) ===' && echo 'Waiting for PLC...' && sleep 5 && sudo docker compose up gateway" C-m

# Pane 2: Snort IDS
tmux send-keys -t "$SESSION:0.2" "echo '=== Snort IDS (Port 503) ===' && echo 'Waiting for PLC...' && sleep 5 && sudo docker compose up snort" C-m

# Pane 3: User terminal with helpful message
tmux send-keys -t "$SESSION:0.3" "cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║  ICS Gateway Demo - User Terminal                              ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  Test Commands:                                                ║
║                                                                ║
║  # Read registers through each path:                           ║
║  echo -ne '\\x00\\x01\\x00\\x00\\x00\\x06\\x01\\x03\\x00\\x00\\x00\\x01' | nc -w 2 localhost 502 | xxd   # seL4    ║
║  echo -ne '\\x00\\x01\\x00\\x00\\x00\\x06\\x01\\x03\\x00\\x00\\x00\\x01' | nc -w 2 localhost 503 | xxd   # Snort   ║
║  echo -ne '\\x00\\x01\\x00\\x00\\x00\\x06\\x01\\x03\\x00\\x00\\x00\\x01' | nc -w 2 localhost 5020 | xxd  # Direct  ║
║                                                                ║
║  # Attack tools:                                               ║
║  ./cve_tools/cve_14462_attack 127.0.0.1 5020  # Attack PLC    ║
║  ./cve_tools/cve_14462_attack 127.0.0.1 502   # Through seL4  ║
║  ./cve_tools/cve_20685_attack 127.0.0.1 503   # DoS Snort     ║
║                                                                ║
║  # Check Snort CPU after attack:                               ║
║  sudo docker exec ics-snort top -b -n 1 | grep snort           ║
║                                                                ║
║  # Restart containers:                                         ║
║  sudo docker compose restart snort                             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
" C-m

# Select the user terminal pane
tmux select-pane -t "$SESSION:0.3"

# Attach to session
tmux attach-session -t "$SESSION"
