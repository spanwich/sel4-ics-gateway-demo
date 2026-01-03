# CLAUDE.md

Technical documentation for Claude Code (claude.ai/code) when working with this repository.

## Project Overview

This is a defensive security research project comparing two ICS gateway architectures:

1. **Protocol-Break (seL4)**: Terminates TCP, validates Modbus semantics, establishes new connection to PLC
2. **Packet-Forwarding (Snort)**: Inspects packets inline, forwards same TCP connection to PLC

The project demonstrates protection against real-world ICS attacks:
- **CVE-2019-14462**: Heap buffer overflow in libmodbus 3.1.2 (PLC vulnerability)
- **CVE-2022-20685**: Integer overflow in Snort Modbus preprocessor (IDS vulnerability)

**Security Context:** Authorized defensive security demonstration. Vulnerable code is intentional for research purposes.

## Research Goals

1. Compare protocol-break vs packet-forwarding architectures for ICS security
2. Demonstrate that IDS solutions themselves can be attacked (CVE-2022-20685)
3. Show advantages of structural validation over signature-based detection
4. Provide reproducible experiments for security research

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
├── snort/                    # Snort IDS (for comparison)
│   ├── Dockerfile            # Snort 2.9.18 (vulnerable to CVE-2022-20685)
│   ├── snort.conf            # Snort config with Modbus preprocessor
│   ├── setup-network.sh      # Packet-forwarding network setup
│   ├── start-snort.sh        # Snort launcher
│   └── rules/                # Modbus detection rules
│       ├── modbus.rules
│       └── local.rules
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
│   ├── Makefile              # Build all attack tools
│   ├── cve_14462_attack.c    # CVE-2019-14462 libmodbus overflow
│   ├── cve_20685_attack.c    # CVE-2022-20685 Snort IDS DoS
│   ├── tcp_segmentation_attack.c  # TCP evasion demonstration
│   ├── latency_benchmark.c   # Gateway latency comparison
│   └── archive/              # Older experimental tools
│
├── scripts/                  # Utility scripts
│   ├── inspect-gateway.sh    # Network debugging
│   ├── debug-traffic.sh      # Traffic analysis
│   ├── test-local.sh         # Local QEMU testing
│   ├── copy-images.sh        # Image management
│   └── run_comparison.sh     # Full comparison experiment
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
| `snort/snort.conf` | Snort config with vulnerable Modbus preprocessor |
| `plc/heating_controller.c` | Modbus server + thermal simulation |
| `cve_tools/cve_14462_attack.c` | CVE-2019-14462 libmodbus heap overflow |
| `cve_tools/cve_20685_attack.c` | CVE-2022-20685 Snort IDS DoS attack |
| `scripts/run_comparison.sh` | Full seL4 vs Snort comparison experiment |

## CVE-2019-14462: libmodbus Heap Buffer Overflow

**Affected:** libmodbus ≤ 3.1.2
**Type:** Heap buffer overflow
**Vector:** Malformed MBAP header length field

### Vulnerability Mechanism

The MBAP (Modbus Application Protocol) header contains a length field that libmodbus trusts without validation:

```
MBAP Header (7 bytes):
┌─────────────────┬─────────────────┬─────────────────┬──────────┐
│ Transaction ID  │ Protocol ID     │ Length          │ Unit ID  │
│ (2 bytes)       │ (2 bytes)       │ (2 bytes)       │ (1 byte) │
└─────────────────┴─────────────────┴─────────────────┴──────────┘
                                      ↑
                                      Attacker controls this field
```

**Attack:**
1. Declare small length (e.g., 60 bytes) in MBAP header
2. Send much larger payload (e.g., 601 bytes)
3. Server allocates 60-byte buffer, receives 601 bytes → heap overflow

### seL4 Protection

The seL4 gateway blocks this by:
1. **Terminating TCP** at the gateway (protocol break)
2. **Parsing MBAP header** and extracting declared length
3. **Comparing lengths**: declared vs actual TCP payload size
4. **Rejecting mismatches** before forwarding to PLC

## CVE-2022-20685: Snort Modbus Preprocessor DoS

**Affected:** Snort < 2.9.19, Snort 3 < 3.1.11.0
**Type:** Integer overflow causing infinite loop
**Vector:** Malformed Modbus Write File Record request

### Vulnerability Mechanism

The vulnerable code is in `ModbusCheckRequestLengths()` in `modbus_decode.c`:

```c
uint16_t bytes_processed;
uint16_t record_length;  // Attacker-controlled from packet

while (bytes_processed < tmp_count) {
    record_length = *(uint16_t*)(payload + offset);
    bytes_processed = 7 + (2 * record_length);  // INTEGER OVERFLOW!
}
```

**Attack:**
1. Send Write File Record (function 0x15) with `record_length = 0xFFFE`
2. Calculation: `bytes_processed = 7 + (2 × 0xFFFE) = 0x20003`
3. Overflow: `0x20003 & 0xFFFF = 0x0003` (uint16_t truncation)
4. Loop condition `3 < tmp_count` remains true → **infinite loop**
5. Snort hangs, stops processing packets → **IDS is blind**

### Why seL4 is Immune

- seL4 has no Modbus preprocessor (no vulnerable code path)
- Minimal attack surface (~1000 LoC vs ~500,000 LoC)
- Simple length validation cannot be exploited this way

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

## Snort IDS Comparison Experiments

The project includes a Snort IDS gateway for comparing protocol-break (seL4) vs packet-forwarding (Snort) architectures.

### Architecture with Snort Gateway

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Docker Network: ics-untrusted (192.168.96.0/24)                             │
│                                                                             │
│   ┌──────────────────────┐    ┌──────────────────────┐                     │
│   │ seL4 Gateway         │    │ Snort IDS Gateway    │                     │
│   │ (192.168.96.10)      │    │ (192.168.96.20)      │                     │
│   │ Port: 502            │    │ Port: 503            │                     │
│   │ Protocol-break       │    │ Packet-forwarding    │                     │
│   └──────────────────────┘    └──────────────────────┘                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Docker Network: ics-protected (192.168.95.0/24)                             │
│                                                                             │
│   ┌──────────────────────────────────────────────────────┐                  │
│   │ PLC Container (192.168.95.2)                         │                  │
│   │ Vulnerable libmodbus 3.1.2                           │                  │
│   └──────────────────────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘

Access Paths:
  • Port 502  → seL4 Gateway (protocol-break)     → PLC
  • Port 503  → Snort Gateway (packet-forward)    → PLC
  • Port 5020 → Direct bypass (no protection)     → PLC
```

### Starting Snort

```bash
# Start Snort container
sudo docker compose up snort

# Or build and run Snort only
cd snort/
docker build -t ics-snort .
```

### CVE-2022-20685: Snort Modbus Preprocessor DoS

The Snort gateway uses version 2.9.18 which is VULNERABLE to CVE-2022-20685 - an integer overflow in the Modbus preprocessor that causes an infinite loop, effectively "blinding" the IDS.

```bash
# Compile attack tools
cd cve_tools/
make

# Attack Snort to blind the IDS
./cve_20685_attack 127.0.0.1 503

# After attack, Snort is frozen and cannot detect subsequent attacks
./cve_14462_attack 127.0.0.1 503  # Attack succeeds undetected
```

### Running Comparison Experiments

```bash
# Run the full comparison experiment script
./scripts/run_comparison.sh
```

This script demonstrates:
1. CVE-2019-14462 blocking by each gateway
2. CVE-2022-20685 IDS DoS attack
3. Post-DoS attack comparison (seL4 still protected, Snort blind)

### Attack Tools

| Tool | Description |
|------|-------------|
| `cve_tools/cve_14462_attack` | CVE-2019-14462 libmodbus heap overflow |
| `cve_tools/cve_20685_attack` | CVE-2022-20685 Snort IDS DoS |
| `cve_tools/tcp_segmentation_attack` | TCP segmentation evasion test |
| `cve_tools/latency_benchmark` | Gateway latency comparison |

### Comparison Results

| Test Case | seL4 Gateway | Snort IDS |
|-----------|--------------|-----------|
| CVE-2019-14462 | BLOCKED (length check) | Needs rule |
| CVE-2022-20685 | IMMUNE (no preprocessor) | VULNERABLE |
| Post-DoS attacks | Still protected | IDS blind |
| TCP segmentation | BLOCKED (TCP terminated) | May evade |
| Unknown variants | BLOCKED (any mismatch) | MISS (no rule) |
| Attack surface | ~1000 LoC | ~500k LoC |

### Protocol-Break vs Packet-Forwarding

**Packet Forwarding (Snort)**:
```
Client ──TCP──> Snort ──TCP──> PLC
         (same connection flows through)
```
- Same TCP connection end-to-end
- Attacker can manipulate TCP state
- Timing attacks possible
- IDS can be attacked (CVE-2022-20685)

**Protocol Break (seL4)**:
```
Client ──TCP1──> seL4 Gateway ──TCP2──> PLC
              (terminates, validates, new connection)
```
- Two independent TCP connections
- Client cannot influence PLC's TCP state
- Validation BEFORE any data reaches PLC
- Minimal attack surface (~1000 LoC)
