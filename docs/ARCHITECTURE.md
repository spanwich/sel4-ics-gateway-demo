# Architecture Documentation

This document provides detailed diagrams and explanations of the seL4 ICS Gateway Demo architecture.

## Network Architecture

### Overview

The demo uses two isolated Docker networks to simulate an industrial control system with a security gateway.

```mermaid
flowchart TB
    subgraph Internet["External Network (Host)"]
        Client[/"SCADA Client\n127.0.0.1"/]
    end

    subgraph Untrusted["Docker: ics-untrusted (192.168.96.0/24)"]
        GW_U["seL4 Gateway\n192.168.96.2\nPort 502"]
        Snort_U["Snort IDS\n192.168.96.20\nPort 503"]
    end

    subgraph Protected["Docker: ics-protected (192.168.95.0/24)"]
        GW_P["seL4 Gateway\n192.168.95.1"]
        Snort_P["Snort IDS\n192.168.95.20"]
        PLC["PLC\n192.168.95.2\nPort 502"]
    end

    Client -->|"Port 502"| GW_U
    Client -->|"Port 503"| Snort_U
    Client -->|"Port 5020"| PLC

    GW_U ---|"Protocol Break"| GW_P
    GW_P -->|"New TCP"| PLC

    Snort_U ---|"NFQUEUE"| Snort_P
    Snort_P -->|"Same TCP"| PLC
```

### Traffic Flow Comparison

```mermaid
flowchart LR
    subgraph ProtocolBreak["Protocol-Break (seL4)"]
        C1[Client] -->|"TCP₁"| S1[seL4]
        S1 -->|"Terminate\nValidate"| S1
        S1 -->|"TCP₂"| P1[PLC]
    end

    subgraph PacketForward["Packet-Forwarding (Snort)"]
        C2[Client] -->|"TCP"| S2[Snort]
        S2 -->|"Inspect\nForward"| P2[PLC]
    end
```

### Port Mapping

```mermaid
flowchart LR
    subgraph Host["Host Ports"]
        P502["502"]
        P503["503"]
        P5020["5020"]
        P5021["5021"]
    end

    subgraph Containers
        GW["seL4 Gateway"]
        SN["Snort IDS"]
        PLC1["PLC (normal)"]
        PLC2["PLC (ASAN)"]
    end

    P502 --> GW
    P503 --> SN
    P5020 --> PLC1
    P5021 --> PLC2

    GW -->|"Protected"| PLC1
    SN -->|"Protected"| PLC1
```

## Docker Container Architecture

### Container Relationships

```mermaid
flowchart TB
    subgraph compose["docker-compose.yml"]
        subgraph plc_container["ics-plc"]
            PLC_APP["heating_controller"]
            LIBMOD["libmodbus 3.1.2\n(vulnerable)"]
            PLC_APP --> LIBMOD
        end

        subgraph gateway_container["ics-gateway"]
            SETUP["setup-network.sh"]
            QEMU["QEMU ARM"]
            SEL4["seL4 Kernel"]
            SETUP --> QEMU
            QEMU --> SEL4
        end

        subgraph snort_container["ics-snort"]
            SNORT_SETUP["setup-network.sh"]
            SNORT_APP["Snort 2.9.18\n(vulnerable)"]
            NFQUEUE["NFQUEUE"]
            SNORT_SETUP --> NFQUEUE
            NFQUEUE --> SNORT_APP
        end
    end

    gateway_container -->|"depends_on"| plc_container
    snort_container -->|"depends_on"| plc_container
```

### Network Attachment

```mermaid
flowchart TB
    subgraph Networks
        UN["ics-untrusted\n192.168.96.0/24"]
        PR["ics-protected\n192.168.95.0/24"]
    end

    subgraph Containers
        GW["ics-gateway"]
        SN["ics-snort"]
        PLC["ics-plc"]
    end

    UN --- GW
    UN --- SN
    PR --- GW
    PR --- SN
    PR --- PLC
```

### seL4 Gateway Internal Architecture

```mermaid
flowchart TB
    subgraph Docker["ics-gateway Container"]
        ETH0["eth0\n(untrusted)"]
        ETH1["eth1\n(protected)"]
        BR0["br0"]
        BR1["br1"]
        TAP0["tap0"]
        TAP1["tap1"]

        subgraph QEMU["QEMU VM"]
            NET0["net0\n192.168.96.2"]
            NET1["net1\n192.168.95.1"]
            subgraph SEL4["seL4 Microkernel"]
                APP["ICS Gateway App"]
            end
            NET0 --- APP
            APP --- NET1
        end

        ETH0 --- BR0
        BR0 --- TAP0
        TAP0 --- NET0

        ETH1 --- BR1
        BR1 --- TAP1
        TAP1 --- NET1
    end
```

### Snort NFQUEUE Architecture

```mermaid
flowchart TB
    subgraph Docker["ics-snort Container"]
        subgraph Kernel["Linux Kernel"]
            NF["netfilter"]
            NFQ["NFQUEUE 0"]
        end

        subgraph Userspace
            SNORT["Snort Process"]
            DAQ["DAQ NFQ Module"]
        end

        NF -->|"FORWARD chain"| NFQ
        NFQ <-->|"verdict"| DAQ
        DAQ <--> SNORT
    end

    IN["Incoming\nPacket"] --> NF
    NF -->|"ACCEPT"| OUT["Outgoing\nPacket"]
```

## CVE Explanations

### CVE-2019-14462: libmodbus Heap Buffer Overflow

**Affected:** libmodbus <= 3.1.2

**Severity:** High (CVSS 9.8)

**Vulnerability Type:** Heap Buffer Overflow

#### How It Works

```mermaid
sequenceDiagram
    participant Attacker
    participant PLC as PLC (libmodbus)
    participant Heap

    Note over PLC: Receives MBAP Header
    Attacker->>PLC: MBAP Header (Length=60)
    PLC->>Heap: malloc(60 bytes)
    Heap-->>PLC: buffer @ 0x1000

    Note over PLC: Trusts Length field!
    Attacker->>PLC: Actual payload (600 bytes)
    PLC->>Heap: memcpy(buffer, data, 600)

    Note over Heap: OVERFLOW!
    Note over Heap: Corrupts adjacent memory
    Note over PLC: CRASH or RCE
```

#### Vulnerable Code

```c
/* libmodbus 3.1.2 - modbus.c */
static int receive_msg(modbus_t *ctx, uint8_t *msg) {
    /* Read MBAP header (7 bytes) */
    rc = recv(ctx->s, msg, 7, 0);

    /* Extract length from header - TRUSTED! */
    length = (msg[4] << 8) | msg[5];

    /* Allocate buffer based on declared length */
    /* BUG: No validation against actual data! */

    /* Read remaining data */
    rc = recv(ctx->s, msg + 7, length - 1, 0);
    /* Attacker sends more than 'length' bytes! */
}
```

#### Attack Packet Structure

```mermaid
packet-beta
  0-15: "Transaction ID (0x0001)"
  16-31: "Protocol ID (0x0000)"
  32-47: "Length (60) - LIES!"
  48-55: "Unit ID (0x01)"
  56-63: "Function Code"
  64-95: "... 600 bytes of overflow data ..."
```

#### Protection Comparison

| Path | Result | Reason |
|------|--------|--------|
| Direct (5020) | **CRASH** | No validation |
| seL4 (502) | **BLOCKED** | Length field validated |
| Snort (503) | **DEPENDS** | Requires specific rule |

---

### CVE-2022-20685: Snort Modbus Preprocessor DoS

**Affected:** Snort < 2.9.19, Snort 3 < 3.1.11.0

**Severity:** High (CVSS 7.5)

**Vulnerability Type:** Integer Overflow causing Infinite Loop

#### How It Works

```mermaid
sequenceDiagram
    participant Attacker
    participant Snort
    participant Kernel as Kernel NFQUEUE

    Attacker->>Kernel: Malicious Modbus packet
    Kernel->>Snort: Packet via NFQUEUE

    Note over Snort: ModbusCheckRequestLengths()
    Note over Snort: record_length = 0xFFFE

    loop Infinite Loop
        Note over Snort: bytes_processed = 7 + (2 × 0xFFFE)
        Note over Snort: = 0x20003
        Note over Snort: Overflow to 0x0003!
        Note over Snort: 3 < tmp_count → continue
    end

    Note over Kernel: Waiting for verdict...
    Note over Kernel: All traffic blocked!
```

#### Vulnerable Code

```c
/* Snort 2.9.18 - modbus_decode.c */
static int ModbusCheckRequestLengths(...) {
    uint16_t bytes_processed = 0;  /* Only 16 bits! */
    uint16_t record_length;

    while (bytes_processed < tmp_count) {
        /* Read record_length from packet */
        record_length = *(uint16_t *)(payload + offset);

        /* INTEGER OVERFLOW BUG! */
        bytes_processed += 7 + (2 * record_length);

        /* When record_length = 0xFFFE:
         * 7 + (2 × 0xFFFE) = 0x20003
         * Truncated to uint16_t: 0x0003
         * Loop condition (3 < tmp_count) stays TRUE!
         */
    }
}
```

#### Integer Overflow Visualization

```mermaid
flowchart TD
    A["record_length = 0xFFFE"] --> B["Calculate: 7 + 2 × 0xFFFE"]
    B --> C["= 7 + 0x1FFFC"]
    C --> D["= 0x20003 (131,075)"]
    D --> E["Truncate to uint16_t"]
    E --> F["0x20003 & 0xFFFF = 0x0003"]
    F --> G["bytes_processed = 3"]
    G --> H{"3 < tmp_count?"}
    H -->|"YES"| I["Continue loop"]
    I --> A
    H -->|"Never NO"| J["Infinite Loop!"]

    style J fill:#f00,color:#fff
```

#### Impact

```mermaid
flowchart LR
    subgraph Before["Before Attack"]
        C1["Client"] -->|"Traffic"| S1["Snort"]
        S1 -->|"Inspected"| P1["PLC"]
    end

    subgraph After["After Attack"]
        C2["Client"] -->|"Traffic"| S2["Snort\n(100% CPU)"]
        S2 -.-x|"BLOCKED"| P2["PLC"]
        Note["All traffic stops!\nNFQUEUE full"]
    end
```

#### Protection Comparison

| Path | Result | Reason |
|------|--------|--------|
| Snort (503) | **VULNERABLE** | Preprocessor has bug |
| seL4 (502) | **IMMUNE** | No Modbus preprocessor |
| Direct (5020) | **N/A** | Not applicable |

---

## Security Architecture Comparison

```mermaid
flowchart TB
    subgraph Traditional["Traditional IDS (Snort)"]
        T_ATK["Attack Surface:\n~500,000 LoC"]
        T_PRE["Preprocessors\n(vulnerable)"]
        T_RULE["Rules\n(signatures)"]
        T_ATK --> T_PRE --> T_RULE
    end

    subgraph Gateway["Protocol-Break (seL4)"]
        G_ATK["Attack Surface:\n~1,000 LoC"]
        G_VAL["Structural\nValidation"]
        G_FV["Formally\nVerified"]
        G_ATK --> G_VAL --> G_FV
    end

    style T_ATK fill:#faa
    style G_ATK fill:#afa
```

### Why Protocol-Break is More Secure

| Aspect | Packet-Forwarding | Protocol-Break |
|--------|-------------------|----------------|
| TCP State | Shared (attackable) | Isolated |
| Attack Surface | Large (full IDS) | Minimal |
| Unknown Attacks | Missed (no signature) | Blocked (structural) |
| IDS Vulnerabilities | Exposed | Not applicable |
| Verification | Testing only | Formal proofs |
