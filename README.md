# 🚗 VANET Clustering and Secure Routing Experiment

A standalone vehicular ad-hoc network research project that models moving
vehicles, roadside units, multi-hop communication, cluster-based routing, and
secure packet delivery using portable C++17.

The project is inspired by the accompanying report, *Performance Analysis of
VANET Clustering Routing Protocol*. It compares AODV-like route flooding with
clustered and secure clustered routing, then generates reproducible measurements
for packet delivery, delay, throughput, and routing overhead.

No NS-2, NAM, Docker, Python packages, or third-party libraries are required.

## 🌟 Why This Project Exists

Vehicles need to exchange safety and traffic information quickly, even when the
network topology changes because of movement. Traditional route discovery can
flood the network with control messages, increasing congestion and packet loss.
Messages from malicious or untrusted vehicles introduce an additional safety risk.

This project explores whether RSU-based clustering can reduce route-discovery
traffic while authentication prevents malicious or modified messages from being
accepted.

The project can:

- Model moving vehicles on horizontal and vertical road corridors
- Rebuild wireless connectivity as vehicles move
- Find current single-hop and multi-hop routes
- Assign each vehicle to its nearest roadside-unit cluster
- Compare flooding, clustered, and secure clustered routing
- Reject traffic from revoked vehicles and simulated tampered packets
- Demonstrate real HMAC-SHA1 generation and verification
- Measure PDR, end-to-end delay, throughput, and routing overhead
- Run ten deterministic experiments for reproducible results
- Export detailed and summarized results as CSV files

## 🏗️ Architecture Overview

High-level experiment workflow:

```text
Create vehicles and RSUs
        ↓
Move vehicles along road corridors
        ↓
Rebuild wireless links
        ↓
Assign vehicles to nearest RSU cluster
        ↓
Generate V2V traffic
        ↓
Select routing strategy
        ↓
Authenticate packets when security is enabled
        ↓
Find multi-hop routes and model contention
        ↓
Collect metrics and write CSV results
```

Core components:

- C++17 simulation engine
- Dynamic vehicle mobility model
- Distance-based wireless connectivity graph
- RSU-based cluster assignment
- Breadth-first multi-hop route discovery
- Trusted-authority and packet-rejection model
- HMAC-SHA1 authentication demonstration
- Deterministic seeded experiment runner
- CSV metrics and comparison output

## 🌐 Routing Strategies

| Strategy | Route Discovery | Security | Primary Goal |
|---|---|---|---|
| AODV-like flooding | Discovery can spread through the connected network | None | Provide a non-clustered baseline |
| Clustered routing | Discovery is scoped using endpoint clusters and RSUs | None | Reduce routing overhead and contention |
| Secure clustered routing | Uses the same cluster-scoped routing | Rejects revoked and tampered traffic | Preserve trusted communication |

## 🤖 Key Features

### 🧭 Dynamic VANET Topology

- Fifteen vehicles move across two horizontal and two vertical corridors
- Four fixed RSUs represent cluster infrastructure
- Vehicle positions change every 0.25 seconds
- Radio links are recalculated after every movement step
- Routes can change as vehicles enter or leave communication range

### 🛣️ Cluster-Based Routing

- Each vehicle joins the nearest RSU cluster
- Source and destination clusters scope route discovery
- Multi-hop paths are calculated using the current connectivity graph
- Lower control traffic reduces modeled wireless contention
- Clustered performance is compared directly with flooding

### 🔐 Secure Communication

- Nodes 3 and 11 represent revoked or malicious vehicles
- A 2.5% random tampering rate models modified packets
- Secure mode rejects malicious traffic before routing
- Legitimate-packet PDR is measured separately from authentication drops
- The smaller demonstration performs actual HMAC-SHA1 signing and verification

### 📊 Metrics and Evaluation

- Packet delivery ratio for legitimate traffic
- Average end-to-end delay in milliseconds
- Delivered application throughput in kilobits per second
- Routing control packets per delivered data packet
- Authentication and routing-drop counts
- Ten seeded runs for deterministic reproduction
- Per-run data and aggregate results exported to CSV

## ⚙️ Experiment Configuration

| Parameter | Value |
|---|---:|
| Simulation area | 1500 m × 1500 m |
| Duration | 20 seconds per run |
| Time step | 0.25 seconds |
| Independent runs | 10 |
| Vehicles | 15 |
| RSUs / clusters | 4 |
| Radio range | 390 m |
| Packet size | 512 bytes |
| Traffic rate | 8 packets per time step |
| Revoked vehicles | Nodes 3 and 11 |
| Random tamper probability | 2.5% |

## 💡 Example Use Cases

- Compare flooding and cluster-scoped route discovery
- Study how authentication affects trusted-packet delivery and delay
- Measure the effect of routing overhead on modeled network contention
- Test different vehicle densities or radio ranges
- Demonstrate V2V and V2I communication concepts
- Use deterministic simulation results in an academic VANET analysis

## 📂 Project Structure

```text
VANETs/
├── vanet_experiment.cpp    # Full routing comparison and CSV generation
├── vanet_sim.cpp           # Compact mobility and HMAC-SHA1 demonstration
├── Makefile                # Build and run commands
├── results/
│   ├── summary.csv         # Aggregate comparison across all runs
│   └── runs.csv            # Results for every seed and protocol
├── project_report (1).pdf  # Original project report
└── README.md               # Project documentation
```

## 🚀 Getting Started

### ✅ Prerequisites

- macOS or Linux
- A C++17-compatible compiler
- `make`

macOS Command Line Tools already provide the required compiler and build tools.
No simulator or package installation is needed.

### 🔧 Build the Project

Clone the repository:

```sh
git clone https://github.com/swathiblrs/VANETs.git
cd VANETs
```

Build both executables:

```sh
make
```

Generated executables are written to `build/`.

### 🧪 Run the Full Experiment

```sh
make experiment
```

This executes all three routing strategies across ten deterministic seeds and
regenerates:

```text
results/summary.csv
results/runs.csv
```

### 🔏 Run the Authentication Demonstration

```sh
make run
```

This smaller program prints vehicle and RSU connectivity, authenticated multi-hop
delivery, and rejection of a packet with a modified authentication code.

## 📈 Reproduced Results

| Protocol | PDR | Delay | Throughput | Overhead |
|---|---:|---:|---:|---:|
| AODV-like flooding | 87.61% | 8.61 ms | 114.83 kbps | 11.82 |
| Clustered routing | 92.77% | 7.84 ms | 121.59 kbps | 7.12 |
| Secure clustered routing | 92.01% | 9.53 ms | 102.54 kbps | 7.27 |

Key observations:

- Clustering reduced control overhead by approximately 40% compared with
  flooding.
- Clustered routing improved PDR by approximately 5.2 percentage points.
- Clustered throughput improved by approximately 5.9%.
- Secure routing rejected 958 malicious or tampered packets across ten runs.
- Secure routing retained a 92.01% PDR for legitimate traffic.
- Authentication added approximately 1.69 ms of average modeled delay.
- Secure throughput is lower because revoked and tampered traffic is intentionally
  excluded from successful delivery.

## 🧮 Metric Definitions

| Metric | Meaning |
|---|---|
| PDR | Delivered legitimate packets ÷ legitimate packets offered × 100 |
| Delay | Average modeled propagation, queueing, and authentication time |
| Throughput | Successfully delivered application bits per second |
| Overhead | Routing control packets generated per delivered data packet |

## ⚡ Performance and Reliability

- Fixed random seeds make every committed result reproducible
- Source builds cleanly with strict compiler warnings enabled
- No network access is needed to run the experiment
- No external runtime or package dependency is used
- Generated build files are isolated under `build/`
- Aggregate and per-run results make calculations auditable

## ⚠️ Model Scope

This is a standalone discrete-event research model, not a packet-accurate IEEE
802.11 implementation and not an NS-2 execution.

Collision probability is estimated using route length and route-control traffic.
Authentication processing and packet rejection are modeled in the comparative
experiment. Actual HMAC-SHA1 computation is demonstrated separately in
`vanet_sim.cpp`.

The generated values must therefore be described as results of this model, not as
real-road measurements or NS-2 results.

## 🔬 Extending the Experiment

Useful extensions include:

- Increase the number or density of vehicles
- Change the radio range
- Vary the number and placement of RSUs
- Add vehicle acceleration and lane changes
- Change malicious-node and tampering rates
- Compare alternative cluster-head selection strategies
- Add privacy-preserving authentication
- Run longer experiments with additional random seeds

Experiment constants are defined near the top of `vanet_experiment.cpp`. After
changing them, rebuild and regenerate the result files:

```sh
make experiment
```
