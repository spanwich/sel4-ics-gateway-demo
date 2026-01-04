# seL4 ICS Gateway Demo

A defensive security research project comparing **protocol-break** vs **packet-forwarding** architectures for protecting industrial control systems from cyber attacks.

> **Documentation:** [Architecture & CVE Details](docs/ARCHITECTURE.md) - Network diagrams, container architecture, and vulnerability explanations.

## Research Motivation

Modern ICS/SCADA systems face sophisticated attacks like [FrostyGoop](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology), which targeted Ukrainian district heating systems via Modbus TCP in January 2024, leaving 600+ households without heat during sub-zero temperatures. Traditional security solutions (firewalls, IDS) use **packet-forwarding** architectures that inspect traffic in-line but maintain a single TCP connection end-to-end.

This project demonstrates an alternative: a **protocol-break** gateway using the formally verified [seL4 microkernel](https://sel4.systems/). By terminating TCP connections and validating protocol semantics before establishing new connections to protected devices, this architecture provides stronger security guarantees.

## Key Findings

| Aspect | Protocol-Break (seL4) | Packet-Forwarding (Snort) |
|--------|----------------------|---------------------------|
| **CVE-2019-14462** | BLOCKED (length validation) | Requires specific rule |
| **CVE-2022-20685** | IMMUNE (no preprocessor) | VULNERABLE (IDS DoS) |
| **Unknown variants** | BLOCKED (structural validation) | MISSED (no signature) |
| **TCP state attacks** | BLOCKED (connection terminated) | Possible |
| **Attack surface** | ~1,000 LoC | ~500,000 LoC |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Docker Network: ics-untrusted (192.168.96.0/24)                             │
│                                                                             │
│   ┌───────────────────────┐       ┌───────────────────────┐                │
│   │ seL4 Gateway          │       │ Snort IDS             │                │
│   │ Port 502              │       │ Port 503              │                │
│   │                       │       │                       │                │
│   │ • Protocol-break      │       │ • Packet-forwarding   │                │
│   │ • TCP termination     │       │ • Inline inspection   │                │
│   │ • Length validation   │       │ • Rule-based detection│                │
│   └───────────┬───────────┘       └───────────┬───────────┘                │
│               │                               │                             │
├───────────────┼───────────────────────────────┼─────────────────────────────┤
│ Docker Network: ics-protected (192.168.95.0/24)                             │
│               │                               │                             │
│               └───────────────┬───────────────┘                             │
│                               ▼                                             │
│               ┌───────────────────────────────┐                             │
│               │ PLC (District Heating)        │                             │
│               │ Vulnerable libmodbus 3.1.2    │                             │
│               │ Port 5020 (direct access)     │                             │
│               └───────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- seL4 gateway kernel image (user-provided)
- ~4GB RAM for QEMU

### 1. Add seL4 Image

```bash
# Place your seL4 kernel image at:
gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt
```

### 2. Build and Run

```bash
# Build all containers
sudo docker compose build

# Start individual containers
sudo docker compose up plc        # PLC only
sudo docker compose up gateway    # seL4 gateway + PLC
sudo docker compose up snort      # Snort IDS + PLC

# Start all
sudo docker compose up
```

### 3. Test Connections

```bash
# Through seL4 gateway (protected - protocol-break)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 502 | xxd

# Through Snort IDS (protected - packet-forwarding)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 503 | xxd

# Direct to PLC (unprotected - vulnerable)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 5020 | xxd
```

## Port Mappings

| Port | Path | Architecture | Protection |
|------|------|--------------|------------|
| 502 | Client → seL4 → PLC | Protocol-break | Validates Modbus structure |
| 503 | Client → Snort → PLC | Packet-forwarding | Rule-based IDS |
| 5020 | Client → PLC | Direct | None (vulnerable) |
| 5021 | Client → PLC (ASAN) | Direct | CVE verification |

## Vulnerability Demonstrations

### CVE-2019-14462: libmodbus Heap Buffer Overflow

The PLC uses intentionally vulnerable libmodbus 3.1.2. The attack exploits trusted MBAP length fields:

```bash
# Build attack tools
cd cve_tools && make

# Attack unprotected PLC (crashes)
./cve_14462_attack 127.0.0.1 5020

# Attack through seL4 (BLOCKED)
./cve_14462_attack 127.0.0.1 502

# Attack through Snort (depends on rules)
./cve_14462_attack 127.0.0.1 503
```

### CVE-2022-20685: Snort Modbus Preprocessor DoS

Snort 2.9.18 has an integer overflow in its Modbus preprocessor that causes an infinite loop, completely blocking all traffic through the IDS:

```bash
# 1. Verify Snort is working (should return Modbus response)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc -w 2 localhost 503 | xxd

# 2. Attack the Snort IDS
./cve_20685_attack 127.0.0.1 503

# 3. Verify Snort is frozen (should timeout with NO response)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc -w 5 localhost 503 | xxd

# 4. Check Snort CPU (should be 100%)
sudo docker exec ics-snort top -b -n 1 | grep snort

# 5. seL4 is IMMUNE (no Modbus preprocessor to exploit)
./cve_20685_attack 127.0.0.1 502  # No effect on seL4

# 6. Restart Snort after demo
sudo docker compose restart snort
```

**Why this is devastating:** Snort uses NFQUEUE inline mode, meaning packets are held in kernel queue until Snort returns a verdict. When Snort hangs, no verdicts are returned, and ALL traffic stops - not just IDS blindness, but complete denial of service.

### Demo Scripts

```bash
# Full demo with 4 quadrants (PLC, seL4, Snort, User terminal)
./scripts/demo.sh

# Snort-only demo with 3 panes (PLC, Snort, User terminal)
./scripts/demo-snort.sh
```

### Full Comparison Experiment

```bash
# Run automated comparison
./scripts/run_comparison.sh
```

## Protocol-Break vs Packet-Forwarding

### Packet-Forwarding (Traditional IDS/IPS)

```
Client ────TCP────► Snort ────TCP────► PLC
          (same connection flows through)
```

- Single TCP connection end-to-end
- Attacker can manipulate TCP state
- IDS can be attacked (CVE-2022-20685)
- Requires signatures for each attack variant

### Protocol-Break (seL4 Gateway)

```
Client ────TCP1────► seL4 ────TCP2────► PLC
              (terminates, validates, new connection)
```

- Two independent TCP connections
- Client cannot influence PLC's TCP state
- Validation before any data reaches PLC
- Catches entire classes of malformed input

## Components

| Directory | Description |
|-----------|-------------|
| `gateway/` | seL4 gateway container (QEMU + seL4 kernel) |
| `snort/` | Snort 2.9.18 IDS container (vulnerable to CVE-2022-20685) |
| `plc/` | District heating simulation (vulnerable libmodbus 3.1.2) |
| `cve_tools/` | Attack tools for CVE demonstrations |
| `scripts/` | Utility and experiment scripts |
| `docs/` | [Architecture documentation](docs/ARCHITECTURE.md) with Mermaid diagrams |

## PLC Simulation

The PLC simulates a district heating controller with Modbus registers:

| Register | Description | R/W |
|----------|-------------|-----|
| HR[0] | Inside temperature (°C ÷10) | R |
| HR[1] | Valve command (0-100%) | R/W |
| HR[2] | Temperature setpoint (°C ÷10) | R/W |
| HR[3] | Mode (0=Manual, 1=Auto) | R/W |
| HR[4] | Outside temperature (°C ÷10) | R |
| HR[5-9] | Status, position, supply temp, runtime, power | R |

## Security Notice

This project contains **intentionally vulnerable code** for defensive security research. The vulnerable libmodbus 3.1.2 and Snort 2.9.18 are included to demonstrate security concepts.

**Do not deploy unprotected components in production environments.**

## References

- [CVE-2019-14462](https://nvd.nist.gov/vuln/detail/CVE-2019-14462) - libmodbus heap buffer overflow
- [CVE-2022-20685](https://nvd.nist.gov/vuln/detail/CVE-2022-20685) - Snort Modbus preprocessor DoS
- [seL4 Microkernel](https://sel4.systems/) - Formally verified microkernel
- [Claroty Team82](https://claroty.com/team82/research/blinding-snort-breaking-the-modbus-ot-preprocessor) - Snort CVE-2022-20685 vulnerability analysis
- [Dragos FrostyGoop Report](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology) - ICS malware analysis (Jan 2024 Ukraine attack)
- [The Record - FrostyGoop](https://therecord.media/frostygoop-malware-ukraine-heat) - 600 Ukrainian households without heat

## License

For authorized defensive security research and educational purposes only.
