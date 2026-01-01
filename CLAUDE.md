# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an seL4 ICS Gateway demonstration project for defensive security research. It demonstrates how a formally verified seL4 microkernel gateway protects vulnerable industrial control systems from cyber attacks (specifically CVE-2019-14462 against libmodbus 3.1.2). The project simulates a FrostyGoop-style attack on a district heating controller.

**Security Context:** This is an authorized defensive security demonstration. The vulnerable code is intentional for educational purposes.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Docker Network: ics-untrusted (192.168.96.0/24)                     │
│   └─ Gateway Container (192.168.96.10)                              │
│        └─ QEMU running seL4 (192.168.96.2 ←→ 192.168.95.1)         │
│             • Terminates TCP connections                            │
│             • Validates Modbus length fields                        │
│             • Blocks malformed packets                              │
├─────────────────────────────────────────────────────────────────────┤
│ Docker Network: ics-protected (192.168.95.0/24)                     │
│   └─ PLC Container (192.168.95.2)                                   │
│        └─ FrostyGoop heating simulation (vulnerable libmodbus)      │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Components:**
- `gateway/`: Ubuntu container running QEMU with seL4 kernel image, bridges Docker networks to tap interfaces
- `plc/`: Debian container with district heating simulation using intentionally vulnerable libmodbus 3.1.2
- `plc/libmodbus_3.1.2/`: Unpatched libmodbus with CVE-2019-14462 (heap buffer overflow)
- `capdl-loader-image-arm-qemu-arm-virt`: User-provided seL4 kernel image

## Build Commands

### PLC Container (District Heating Simulation)
```bash
cd plc/
make release              # Normal build
make asan                 # AddressSanitizer build for CVE proof
make clean                # Clean build artifacts

# Docker builds
docker build --target normal -t ics-plc:normal .
docker build --target asan -t ics-plc:asan .
```

### libmodbus (Intentionally Vulnerable)
```bash
cd plc/libmodbus_3.1.2/
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
make install && sudo ldconfig
```

### Gateway Container
```bash
cd gateway/
docker build -t ics-gateway .
```

## Running the Demo

The gateway requires a user-provided seL4 image at `gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt`.

**Port Mappings:**
- `502`: Protected access through seL4 gateway
- `5020`: Direct bypass to vulnerable PLC
- `5021`: ASAN-instrumented PLC for CVE verification

## Project Structure

```
.
├── CLAUDE.md                 # Technical documentation (this file)
├── README.md                 # User-facing documentation
├── docker-compose.yml        # Container orchestration
├── .gitignore
│
├── gateway/                  # seL4 gateway container
│   ├── Dockerfile
│   ├── setup-network.sh      # Bridge/tap/iptables configuration
│   ├── start-gateway.sh      # QEMU launcher
│   └── sel4-image/           # User-provided seL4 kernel
│
├── plc/                      # PLC container (vulnerable)
│   ├── Dockerfile
│   ├── Makefile
│   ├── heating_controller.c  # Main program
│   ├── process_sim.c/h       # Thermal physics model
│   ├── display.c/h           # Console visualization
│   └── libmodbus_3.1.2/      # Embedded vulnerable libmodbus
│
├── cve_tools/                # CVE attack tools
│   ├── cve_14462_attack.c    # Self-contained attack (no dependencies)
│   └── archive/              # Older experimental tools
│
├── scripts/                  # Utility scripts
│   ├── inspect-gateway.sh    # Network debugging
│   ├── debug-traffic.sh      # Traffic analysis
│   ├── test-local.sh         # Local QEMU testing
│   └── copy-images.sh        # Image management
│
└── archive/                  # Planning documents
    ├── frostygoop-heating-simulation.md
    └── sel4-ics-demo-plan.md
```

### Key Files

| File | Purpose |
|------|---------|
| `gateway/setup-network.sh` | Creates bridges, tap interfaces, policy routing |
| `gateway/start-gateway.sh` | Launches QEMU with seL4 kernel |
| `plc/heating_controller.c` | Modbus server + thermal simulation |
| `cve_tools/cve_14462_attack.c` | Self-contained CVE-2019-14462 exploit |

## CVE-2019-14462 Details

The vulnerability is a heap buffer overflow in libmodbus ≤ 3.1.2 where the MBAP header length field is trusted without validation. An attacker can declare a small length (e.g., 60 bytes) while sending a much larger payload (e.g., 601 bytes), causing memory corruption.

The seL4 gateway blocks this by:
1. Terminating TCP at the gateway (protocol break)
2. Parsing the MBAP header and extracting the declared length
3. Comparing declared vs actual TCP payload size
4. Rejecting mismatched packets before forwarding

## Modbus Register Map (Heating Simulation)

| Register | Description | R/W | Scale |
|----------|-------------|-----|-------|
| HR[0] | Inside temperature (°C) | R | ÷10 |
| HR[1] | Valve command (0-100%) | R/W | 1 |
| HR[2] | Temperature setpoint (°C) | R/W | ÷10 |
| HR[3] | Mode (0=Manual, 1=Auto) | R/W | 1 |
| HR[4] | Outside temperature (°C) | R | ÷10 |
| HR[5] | Status code | R | 1 |
| HR[6] | Actual valve position (%) | R | 1 |
| HR[7] | Supply temperature (°C) | R | ÷10 |
| HR[8] | Runtime (seconds) | R | 1 |
| HR[9] | Heater power (kW) | R | ÷10 |

## Network Configuration

| Component | IP Address | Network |
|-----------|------------|---------|
| Gateway container eth0/eth1 | 192.168.96.10 / 192.168.95.10 | Dynamically assigned |
| Bridge br0 | 192.168.96.10 | ics-untrusted |
| Bridge br1 | 192.168.95.10 | ics-protected |
| seL4 net0 (QEMU tap0) | 192.168.96.2 | Untrusted side |
| seL4 net1 (QEMU tap1) | 192.168.95.1 | Protected side |
| PLC container | 192.168.95.2 | ics-protected |

## Gateway Network Architecture (Detailed)

### Bridge Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Gateway Container                                                           │
│                                                                             │
│  ┌─────────────────────────┐         ┌─────────────────────────┐           │
│  │ br0 (192.168.96.10)     │         │ br1 (192.168.95.10)     │           │
│  │   ├─ eth* (untrusted)   │         │   ├─ eth* (protected)   │           │
│  │   └─ tap0 ──────────────┼────┐    │   └─ tap1 ──────────────┼────┐      │
│  └─────────────────────────┘    │    └─────────────────────────┘    │      │
│                                 │                                    │      │
│  ┌──────────────────────────────┴────────────────────────────────────┴───┐  │
│  │ QEMU (ARM virt, Cortex-A15)                                           │  │
│  │   ├─ net0 (192.168.96.2) ←── virtio-net ←── tap0                     │  │
│  │   └─ net1 (192.168.95.1) ←── virtio-net ←── tap1                     │  │
│  │                                                                       │  │
│  │   seL4 Microkernel + ICS Gateway Application                         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Dynamic Interface Detection

Docker does not guarantee which physical interface (eth0/eth1) gets which network. The `setup-network.sh` script auto-detects the interface assignment by checking IP addresses:

```bash
# Script detects which eth has 192.168.96.x (untrusted) vs 192.168.95.x (protected)
# Then assigns bridges accordingly:
#   br0 = untrusted network interface + tap0
#   br1 = protected network interface + tap1
```

### Policy Routing for Destination Preservation

The seL4 gateway expects to see the **PLC's destination IP (192.168.95.2)** in incoming packets, not its own IP. This mimics real hardware deployment where packets to the PLC are forwarded through seL4.

**Problem:** Standard DNAT would rewrite destination to seL4's IP (192.168.96.2), causing seL4 to forward to the wrong destination.

**Solution:** Policy routing with packet marking:

```bash
# 1. DNAT to PLC's IP (preserves correct destination for seL4)
iptables -t nat -A PREROUTING -p tcp --dport 502 -j DNAT --to-destination 192.168.95.2:502

# 2. Mark packets that need special routing
iptables -t mangle -A PREROUTING -d 192.168.95.2 -p tcp --dport 502 -j MARK --set-mark 100

# 3. Policy routing rule for marked packets
ip rule add fwmark 100 table 100

# 4. Custom route: send marked 192.168.95.2 traffic to seL4 via br0
ip route add 192.168.95.2/32 via 192.168.96.2 dev br0 table 100
```

### Traffic Flow

```
SCADA Client
    │
    ▼ Connect to 127.0.0.1:502
┌─────────────────────────────────────────────────────────────────┐
│ Host                                                            │
│   Docker port mapping: 502 → Gateway container                  │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ Packet arrives at Gateway container
┌─────────────────────────────────────────────────────────────────┐
│ Gateway Container - iptables                                    │
│   1. PREROUTING/DNAT: dest → 192.168.95.2:502                  │
│   2. MANGLE: mark packet with fwmark 100                        │
│   3. Policy route: fwmark 100 → table 100                       │
│   4. Route table 100: 192.168.95.2 via 192.168.96.2 dev br0    │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ Packet forwarded to seL4 via br0/tap0
┌─────────────────────────────────────────────────────────────────┐
│ seL4 Gateway (net0: 192.168.96.2)                               │
│   • Receives packet with dest=192.168.95.2:502                  │
│   • Terminates TCP connection                                   │
│   • Validates Modbus MBAP header (length field check)           │
│   • If valid: initiates NEW connection to PLC                   │
│   • If invalid: blocks and logs attack                          │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ seL4 connects to PLC via net1/tap1/br1
┌─────────────────────────────────────────────────────────────────┐
│ PLC Container (192.168.95.2:502)                                │
│   • Receives validated Modbus request                           │
│   • Processes and responds                                      │
│   • Response flows back through seL4 to client                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Policy Routing is Required

| Approach | seL4 sees dest= | seL4 forwards to | Result |
|----------|-----------------|------------------|--------|
| Simple DNAT to 192.168.96.2 | 192.168.96.2 | 192.168.96.2 (wrong!) | Connection fails |
| Policy routing + DNAT to 192.168.95.2 | 192.168.95.2 | 192.168.95.2 (correct) | Works |

The seL4 gateway uses the destination IP from incoming packets to determine where to forward validated traffic. By preserving the PLC's IP (192.168.95.2) as the destination, seL4 correctly forwards via net1 to the actual PLC.

## Testing the Gateway

### Start the stack
```bash
sudo docker compose build
sudo docker compose up
```

### Test protected access (through seL4)
```bash
# Using modbus client (e.g., modscan, mbpoll)
modscan -t 127.0.0.1 -p 502

# Or using netcat for raw Modbus
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 502 | xxd
```

### Test direct bypass (unprotected - for comparison)
```bash
modscan -t 127.0.0.1 -p 5020
```

### Debugging

Inspect network configuration:
```bash
sudo ./scripts/inspect-gateway.sh
```

Capture traffic on bridges:
```bash
# Untrusted side (client → seL4)
sudo docker exec ics-gateway tcpdump -i br0 -n -e

# Protected side (seL4 → PLC)
sudo docker exec ics-gateway tcpdump -i br1 -n -e
```

### Local testing without Docker
```bash
./scripts/test-local.sh
# Connects to localhost:5502, forwards to PLC on localhost:5020
```

### Testing CVE-2019-14462 Attack

```bash
# Compile the attack tool
gcc -o cve_tools/cve_14462_attack cve_tools/cve_14462_attack.c

# Test against unprotected PLC (should cause crash/overflow)
./cve_tools/cve_14462_attack 127.0.0.1 5020

# Test through seL4 gateway (should be blocked)
./cve_tools/cve_14462_attack 127.0.0.1 502
```
