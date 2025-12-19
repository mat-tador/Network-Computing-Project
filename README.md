# Network Computing Project: eBPF/XDP Layer 4 Load Balancer

**Author:** Mattia Fiore

This repository contains a high-performance **Layer 4 Load Balancer** implemented using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**.

The project demonstrates advanced kernel-bypass networking by intercepting packets at the driver level, performing load balancing decisions based on a custom "Least Loaded" algorithm, and forwarding traffic using **IPIP encapsulation**.

## 📖 Overview

The Load Balancer attaches to a network interface using XDP. It processes incoming UDP traffic destined for a configured **Virtual IP (VIP)** and distributes it across a pool of backend servers defined in a configuration file.

### Key Features

* **⚡ High Performance:** Runs directly in the Linux kernel via XDP, avoiding the overhead of the standard network stack for packet processing.
* **⚖️ Dynamic Load Balancing:** Implements a **"Least Loaded" algorithm**. The system tracks the number of active flows and packets for each backend and directs new flows to the server with the lowest load metric ($Load = \frac{Packets}{Flows}$).
* **🔗 Session Persistence (Stickiness):** Utilizes a Connection Tracking Hash Map to ensure that packets belonging to the same flow (Source IP/Port, Dest IP/Port) are consistently routed to the same backend.
* **📦 IPIP Encapsulation:** Uses IP-in-IP tunneling to forward packets, preserving the original client IP address when reaching the backend.
* **⚙️ User-Space Control Plane:** A C application manages the BPF lifecycle, loads configuration dynamically from `config.yaml`, and populates BPF maps.

## 📂 Repository Structure

| File | Description |
| :--- | :--- |
| `ebpf/l4_lb.bpf.c` | **Core XDP Logic**. Handles packet parsing, flow lookup, load calculation, header manipulation (IPIP), and transmission (`XDP_TX`). |
| `l4_lb.c` | **Userspace Loader**. Loads the BPF program into the kernel, parses the configuration, and manages BPF maps. |
| `config.yaml` | Configuration file defining the VIP and the list of Backend IPs. |
| `create-topo.sh` | Script to set up the virtual network topology (veth pairs) for local testing. |
| `send.py` | Python script (Scapy) to generate traffic flows and visualize distribution. |
| `receive.py` | Python script to sniff and verify packets on the backend interfaces. |
| `Makefile` | Automates the build process for both BPF bytecode and the userspace loader. |

## 🛠️ Prerequisites

To build and run this project, you need a Linux environment with the following dependencies:

* **Clang/LLVM**: For compiling BPF programs.
* **libbpf**: Library for loading and interacting with BPF objects.
* **libyaml**: For parsing the configuration file.
* **libnl-3**: Netlink library.
* **Python 3**: With `scapy`, `matplotlib`, and `pyyaml` for the testing scripts.

## 🚀 Build Instructions

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/mat-tador/Network-Computing-Project.git](https://github.com/mat-tador/Network-Computing-Project.git)
    cd Network-Computing-Project
    ```

2.  **Compile the project:**
    Use the provided Makefile to compile the BPF program and the loader.
    ```bash
    make
    ```

## 💻 Usage Guide

### 1. Setup the Network Topology
Create the virtual interfaces (`veth` pairs) required for testing. This script utilizes `create_veth` functions to prepare the environment:
```bash
sudo ./create-topo.sh
```
### 2. Configuration
Edit `config.yaml` to define your Virtual IP (VIP) and the backend server pool. The load balancer will distribute traffic destined for this VIP among the listed backends.

```yaml
vip: 123.168.9.8
backends:
  - ip: 10.0.1.1
  - ip: 10.0.2.2
  - ip: 10.0.3.3
  - ip: 10.0.4.4
  - ip: 10.0.5.5
```

### 3. Start the Load Balancer
Run the userspace loader to compile the BPF program, load the maps, and attach the XDP hook to the network interface.

```bash
# Syntax: sudo ./l4_lb --config <config_file> --iface1 <interface>
sudo ./l4_lb --config config.yaml --iface1 veth1
```

- --config: Path to the YAML configuration file.

- --iface1: The network interface to attach to (default is veth1 if using the provided topology script).

The program will remain running to monitor traffic and maintain the BPF maps. Press Ctrl+C to stop it and detach the program.
4. Testing & Verification

The repository includes Python scripts (based on Scapy) to generate traffic and verify the load balancing logic.

Terminal 1: Start the Load Balancer
```bash
sudo ./l4_lb
```

Terminal 2: Generate Traffic Use send.py to generate UDP flows. The script simulates multiple clients sending packets to the VIP.
```bash
# Generate 10 distinct flows on interface veth1
sudo python3 send.py -i veth1 -f 10
```

- -i: Interface to send packets on.

- -f: Number of unique flows (source IPs) to simulate.

- -p: (Optional) Fixed number of packets per flow. If omitted, a random number is sent.

The script will automatically generate a bar_chart.png image showing the distribution of packets across flows.

Terminal 3: Monitor Backend (Optional) You can use receive.py to sniff packets on a specific interface to verify they are being forwarded correctly.
```bash
sudo python3 receive.py veth1
```

## 🧠 Technical Deep Dive


The core logic resides in ebpf/l4_lb.bpf.c and operates as follows:

Packet Parsing:

    The XDP program intercepts packets at the driver level.

    It filters for IPv4 UDP traffic destined for the configured VIP.

    ARP requests are passed to the OS stack (XDP_PASS) to allow neighbor discovery.

Flow Management:

    A Flow Map (Hash Map) tracks active connections using a 4-tuple key {SrcIP, DstIP, SrcPort, DstPort}.

    Existing Flows: If a match is found, the packet is routed to the previously assigned backend to maintain session affinity.

    New Flows: If no entry exists, the "Least Loaded" algorithm selects a backend.

Load Balancing Algorithm (Least Loaded):

    The system tracks metrics for each backend: flows_count and pkts_count.

    It calculates the load metric: Load=TotalFlowsTotalPackets​.

    The backend with the lowest load score is selected for the new flow.

Forwarding (IPIP Encapsulation):

    The program uses bpf_xdp_adjust_head to expand the packet headroom.

    A new IP header is pushed onto the packet (IP-in-IP), with the Destination IP set to the selected Backend's real IP.

    The packet is transmitted out via XDP_TX.

Developed for the Network Computing course.
