The number of accidents are increasing in large numbers. The lifesaving vehicles like ambulances are seen stuck in traffic and many have lost life because the patients could not make it to hospital on time. This is partially because vehicles are independently controlled, for example any accidents happen in highways then that would create road blockage and heavy traffic and as there is no mechanism to gather and process traffic information and provide warnings, so in order to improvise the traffic conditions VANET is used.

Objectives

• To implement existing VANETS clustering routing protocol.

• To enhance the performance of clustering routing protocol with respect to throughput, delay, PDR & overhead.

• Performance comparison of existing and enhanced clustering protocols.

• To implement the security parameter.

## Standalone implementation

The repository includes a portable C++17 VANET demonstration. It models moving
vehicles and road-side units, rebuilds wireless links at every time step, finds
single-hop or multi-hop routes, and authenticates messages with HMAC-SHA1. It also
demonstrates rejection of a packet whose authentication code has been modified.

This implementation is a lightweight executable version of the authentication and
routing concepts in the report. It is not an NS-2 simulation and does not reproduce
the report's NS-2/NAM graphs.

### Build and run

Requirements: a C++17 compiler and `make`.

```sh
make clean
make
./build/vanet_sim
```

Or compile directly:

```sh
c++ -std=c++17 -O2 -Wall -Wextra -pedantic vanet_sim.cpp -o vanet_sim_local
./vanet_sim_local
```

The old checked-in `vanet_sim` executable may have been built for a different
operating system or CPU. Rebuild it from source on the target machine.
