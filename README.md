# seL4 ICS Gateway Demo

A defensive security demonstration showing how a formally verified seL4 microkernel gateway protects vulnerable industrial control systems from cyber attacks.

## Overview

This project demonstrates protection against **CVE-2019-14462** (heap buffer overflow in libmodbus 3.1.2) using an seL4-based security gateway. It simulates a FrostyGoop-style attack on a district heating controller.

```
┌─────────────────────────────────────────────────────────────────────┐
│ Untrusted Network (192.168.96.0/24)                                 │
│   └─ SCADA Client                                                   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │ seL4 Gateway (QEMU)                                         │   │
│   │   • Terminates TCP connections                              │   │
│   │   • Validates Modbus MBAP length fields                     │   │
│   │   • Blocks malformed packets (CVE-2019-14462)               │   │
│   └─────────────────────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
├─────────────────────────────────────────────────────────────────────┤
│ Protected Network (192.168.95.0/24)                                 │
│   └─ PLC (District Heating Controller)                              │
│        └─ Vulnerable libmodbus 3.1.2                                │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose v2
- seL4 gateway kernel image (user-provided)
- ~4GB RAM for QEMU

## Quick Start

### 1. Add seL4 Image

Place your seL4 kernel image at:
```
gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt
```

### 2. Build and Run

```bash
# Build all containers
sudo docker compose build

# Start the stack
sudo docker compose up
```

### 3. Test Connection

```bash
# Through seL4 gateway (protected)
modscan -t 127.0.0.1 -p 502

# Direct to PLC (unprotected - for comparison)
modscan -t 127.0.0.1 -p 5020
```

## Port Mappings

| Port | Path | Protection |
|------|------|------------|
| 502 | Client → seL4 Gateway → PLC | Protected (validates Modbus) |
| 5020 | Client → PLC (direct) | Unprotected (vulnerable) |
| 5021 | Client → PLC (ASAN build) | For CVE verification |

## Architecture

### Components

| Component | Description |
|-----------|-------------|
| `gateway/` | Ubuntu container with QEMU running seL4 |
| `plc/` | Debian container with vulnerable heating controller |
| `plc/libmodbus_3.1.2/` | Unpatched libmodbus (CVE-2019-14462) |

### Network Configuration

| Component | IP Address | Network |
|-----------|------------|---------|
| seL4 net0 | 192.168.96.2 | Untrusted (client-facing) |
| seL4 net1 | 192.168.95.1 | Protected (PLC-facing) |
| PLC | 192.168.95.2 | Protected |

### Traffic Flow

```
Client (127.0.0.1:502)
    │
    ▼ Docker port mapping
Gateway Container
    │
    ▼ iptables DNAT + Policy Routing
seL4 Gateway (192.168.96.2)
    │
    ├─ VALID request → Forward to PLC
    │
    └─ INVALID request → Block & Log

    │
    ▼ New TCP connection
PLC (192.168.95.2:502)
```

## CVE-2019-14462

### Vulnerability

libmodbus 3.1.2 trusts the MBAP header length field without validation. An attacker can:

1. Declare a small length (e.g., 60 bytes) in the MBAP header
2. Send a much larger payload (e.g., 601 bytes)
3. Cause heap buffer overflow in the server

### Protection

The seL4 gateway blocks this attack by:

1. **Terminating TCP** - Protocol break between client and PLC
2. **Parsing MBAP header** - Extracts declared length field
3. **Validating length** - Compares declared vs actual payload size
4. **Blocking mismatches** - Drops packets before reaching PLC

## PLC Simulation (District Heating)

The PLC simulates a district heating controller with these Modbus registers:

| Register | Description | R/W |
|----------|-------------|-----|
| HR[0] | Inside temperature (°C ÷10) | R |
| HR[1] | Valve command (0-100%) | R/W |
| HR[2] | Temperature setpoint (°C ÷10) | R/W |
| HR[3] | Mode (0=Manual, 1=Auto) | R/W |
| HR[4] | Outside temperature (°C ÷10) | R |
| HR[5] | Status code | R |
| HR[6] | Actual valve position (%) | R |
| HR[7] | Supply temperature (°C ÷10) | R |
| HR[8] | Runtime (seconds) | R |
| HR[9] | Heater power (kW ÷10) | R |

## Building Individual Components

### Gateway Container
```bash
cd gateway/
docker build -t ics-gateway .
```

### PLC Container
```bash
cd plc/

# Normal build
docker build --target normal -t ics-plc:normal .

# AddressSanitizer build (for CVE proof)
docker build --target asan -t ics-plc:asan .
```

### libmodbus (for local testing)
```bash
cd plc/libmodbus_3.1.2/
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install && sudo ldconfig
```

## Testing CVE-2019-14462

### Compile Attack Tool
```bash
gcc -o cve_tools/cve_14462_attack cve_tools/cve_14462_attack.c
```

### Test Against Unprotected PLC (should crash)
```bash
./cve_tools/cve_14462_attack 127.0.0.1 5020
```

### Test Through seL4 Gateway (should be blocked)
```bash
./cve_tools/cve_14462_attack 127.0.0.1 502
```

## Debugging

### Inspect Gateway Network
```bash
sudo ./scripts/inspect-gateway.sh
```

### Capture Traffic
```bash
# Client → seL4 (untrusted side)
sudo docker exec ics-gateway tcpdump -i br0 -n -e

# seL4 → PLC (protected side)
sudo docker exec ics-gateway tcpdump -i br1 -n -e
```

### View Logs
```bash
# Gateway log (seL4 output)
sudo docker compose logs gateway

# PLC log
sudo docker compose logs plc
```

### Local Testing (without Docker)
```bash
# Start PLC on port 5020
sudo docker compose up plc

# Run seL4 locally with QEMU
./scripts/test-local.sh

# Test via localhost:5502
modscan -t 127.0.0.1 -p 5502
```

## Files

```
.
├── CLAUDE.md               # Detailed technical documentation
├── README.md               # This file
├── docker-compose.yml      # Container orchestration
│
├── gateway/                # seL4 gateway container
│   ├── Dockerfile
│   ├── setup-network.sh    # Bridge/tap/iptables setup
│   ├── start-gateway.sh    # QEMU launcher
│   └── sel4-image/         # Place seL4 kernel here
│
├── plc/                    # Vulnerable PLC container
│   ├── Dockerfile
│   ├── Makefile
│   ├── heating_controller.c
│   ├── process_sim.c/h     # Thermal simulation
│   ├── display.c/h         # Console visualization
│   └── libmodbus_3.1.2/    # Vulnerable library (embedded)
│
├── cve_tools/              # CVE attack tools
│   ├── cve_14462_attack.c  # Self-contained exploit
│   └── archive/            # Older experimental tools
│
├── scripts/                # Utility scripts
│   ├── inspect-gateway.sh
│   ├── debug-traffic.sh
│   └── test-local.sh
│
└── archive/                # Planning documents
```

## Security Notice

This project contains **intentionally vulnerable code** for educational and defensive security research purposes. The vulnerable libmodbus 3.1.2 is included to demonstrate the protection capabilities of the seL4 gateway.

**Do not deploy the unprotected PLC (port 5020) in production environments.**

## License

This project is for authorized defensive security research and educational purposes.

## References

- [CVE-2019-14462](https://nvd.nist.gov/vuln/detail/CVE-2019-14462) - libmodbus heap buffer overflow
- [seL4 Microkernel](https://sel4.systems/) - Formally verified microkernel
- [FrostyGoop](https://www.cisa.gov/news-events/cybersecurity-advisories) - ICS malware targeting heating systems
