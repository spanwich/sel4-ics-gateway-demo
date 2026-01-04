# Docker Container Architecture

This document describes the Docker container relationships and internal architecture.

## Container Overview

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

## Container Dependencies

```mermaid
flowchart LR
    PLC["ics-plc\n(must start first)"]
    GW["ics-gateway"]
    SN["ics-snort"]

    GW -->|"depends_on"| PLC
    SN -->|"depends_on"| PLC
```

| Container | Depends On | Reason |
|-----------|------------|--------|
| ics-plc | - | Base service |
| ics-gateway | ics-plc | Needs PLC to forward traffic to |
| ics-snort | ics-plc | Needs PLC to forward traffic to |

## Network Attachment

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

| Container | ics-untrusted | ics-protected |
|-----------|---------------|---------------|
| ics-gateway | Yes | Yes |
| ics-snort | Yes | Yes |
| ics-plc | No | Yes |

## seL4 Gateway Internal Architecture

The gateway container runs QEMU with the seL4 microkernel inside.

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

### Bridge Configuration

| Bridge | Interface | TAP | QEMU NIC | Purpose |
|--------|-----------|-----|----------|---------|
| br0 | eth0 (untrusted) | tap0 | net0 | Client-facing |
| br1 | eth1 (protected) | tap1 | net1 | PLC-facing |

## Snort NFQUEUE Architecture

Snort operates in inline IPS mode using NFQUEUE.

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

### NFQUEUE Flow

```mermaid
sequenceDiagram
    participant Client
    participant Kernel as Linux Kernel
    participant NFQ as NFQUEUE
    participant Snort
    participant PLC

    Client->>Kernel: TCP Packet
    Kernel->>NFQ: Forward to queue 0
    NFQ->>Snort: Packet for inspection
    Snort->>Snort: Analyze with preprocessors
    Snort->>NFQ: Verdict (ACCEPT/DROP)
    NFQ->>Kernel: Apply verdict
    Kernel->>PLC: Forward packet
```

## PLC Container

Simple container running the vulnerable heating controller.

```mermaid
flowchart TB
    subgraph Docker["ics-plc Container"]
        subgraph App["heating_controller"]
            MODBUS["Modbus TCP Server\nPort 502"]
            SIM["Process Simulation"]
            DISPLAY["Console Display"]
        end

        subgraph Lib["libmodbus 3.1.2"]
            VULN["CVE-2019-14462\nHeap Overflow"]
        end

        MODBUS --> Lib
        SIM --> MODBUS
        DISPLAY --> SIM
    end
```

## Container Capabilities

| Container | Privileged | NET_ADMIN | Reason |
|-----------|------------|-----------|--------|
| ics-gateway | Yes | Yes | Bridge/tap creation, QEMU |
| ics-snort | Yes | Yes | NFQUEUE, iptables |
| ics-plc | No | No | Simple application |
