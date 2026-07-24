# 🚗 VANET Cloud Simulator

An interactive cloud-hosted vehicular ad-hoc network simulator for moving
vehicles, roadside units, multi-hop communication, cluster-based routing,
malicious-traffic detection, and live performance graphs.

## 🌐 Live Cloud Application

### [Open the VANET Cloud Simulator](https://vanet-cloud-simulator.ssjgssjv.chatgpt.site)

The hosted application runs entirely in the browser. It does not require NS-2,
NAM, Docker, a compiler, or any software installation. The private deployment
may ask you to sign in before opening the simulator.

Use the cloud dashboard to:

- Animate vehicles, RSUs, clusters, and changing wireless links
- Switch between AODV-like flooding, clustered routing, and secure clustered routing
- Adjust the vehicle count, radio range, and malicious-traffic percentage
- Run a complete 20-second network scenario
- View live PDR, delay, throughput, overhead, and threat-blocking metrics
- Generate protocol-comparison and time-series graphs
- Export the current simulation result as a CSV file

The repository also retains the portable C++17 implementation for reproducible
offline execution and verification of the underlying routing and authentication
logic.

## 🌟 Why This Project Exists

Vehicles need to exchange safety and traffic information quickly, even when the
network topology changes because of movement. Traditional route discovery can
flood the network with control messages, increasing congestion and packet loss.
Messages from malicious or untrusted vehicles introduce an additional safety risk.

This project explores whether RSU-based clustering can reduce route-discovery
traffic while authentication prevents malicious or modified messages from being
accepted.

The project can:

- Run as a free cloud-hosted browser application
- Display the network and result graphs interactively
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

- Browser-based cloud simulation dashboard
- HTML Canvas network animation and performance graphs
- Adjustable scenario controls and CSV export
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

- Live interactive graphs in the hosted dashboard
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
- Present a complete working VANET demonstration with downloadable results

## 📂 Project Structure

```text
VANETs/
├── web/
│   ├── static/
│   │   ├── index.html      # Cloud dashboard interface
│   │   ├── app.js          # Browser simulation and graph engine
│   │   ├── styles.css      # Responsive dashboard design
│   │   └── og.png          # Link-sharing preview
│   ├── worker/             # Cloud request handler
│   ├── scripts/            # Deployment build script
│   └── .openai/            # Cloud hosting configuration
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

### ☁️ Use Online — Recommended

Open the hosted application:

**[https://vanet-cloud-simulator.ssjgssjv.chatgpt.site](https://vanet-cloud-simulator.ssjgssjv.chatgpt.site)**

Choose a routing protocol, adjust the scenario, and select **Run simulation**.
The network animation and graphs are calculated directly in the browser. Select
**Download results CSV** to save the displayed result.

### 💻 Run the C++ Version Locally — Optional

#### ✅ Prerequisites

- macOS or Linux
- A C++17-compatible compiler
- `make`

macOS Command Line Tools already provide the required compiler and build tools.
No simulator or package installation is needed.

#### 🔧 Build the Project

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

#### 🧪 Run the Full Experiment

```sh
make experiment
```

This executes all three routing strategies across ten deterministic seeds and
regenerates:

```text
results/summary.csv
results/runs.csv
```

#### 🔏 Run the Authentication Demonstration

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

- Cloud dashboard requires no local software installation
- Simulation data remains in the browser and is not uploaded
- Interactive metrics and graphs update when scenario inputs change
- Results can be exported directly as CSV
- Fixed random seeds make every committed result reproducible
- Source builds cleanly with strict compiler warnings enabled
- No network access is needed to run the experiment
- No external runtime or package dependency is used
- Generated build files are isolated under `build/`
- Aggregate and per-run results make calculations auditable

## ⚠️ Model Scope

The cloud application is an interactive reconstruction of the original VANET
project idea. It is not the lost NS-2 source code and does not claim that its
browser-generated values were produced by NS-2.

The browser dashboard calculates results from the selected protocol, network
density, radio range, malicious-traffic level, moving topology, and modeled
contention. The C++ experiment provides deterministic comparison runs, while
`vanet_sim.cpp` separately demonstrates actual HMAC-SHA1 computation.

Generated values should be described as cloud-simulator results rather than
real-road measurements or recovered NS-2 results.

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
