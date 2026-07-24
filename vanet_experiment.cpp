#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <queue>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr int kVehicles = 15;
constexpr int kRsus = 4;
constexpr int kNodes = kVehicles + kRsus;
constexpr double kDuration = 20.0;
constexpr double kStep = 0.25;
constexpr double kRange = 390.0;
constexpr int kPacketBytes = 512;

enum class Protocol { Flooding, Clustered, SecureClustered };

struct Node {
    double x{};
    double y{};
    double vx{};
    double vy{};
    bool rsu{};
    int cluster{-1};
};

struct Metrics {
    std::uint64_t offered{};
    std::uint64_t legitimate{};
    std::uint64_t delivered{};
    std::uint64_t auth_drops{};
    std::uint64_t route_drops{};
    std::uint64_t control_packets{};
    double delay_sum{};

    double pdr() const {
        return legitimate ? 100.0 * delivered / legitimate : 0.0;
    }
    double average_delay_ms() const {
        return delivered ? 1000.0 * delay_sum / delivered : 0.0;
    }
    double throughput_kbps() const {
        return delivered * kPacketBytes * 8.0 / kDuration / 1000.0;
    }
    double overhead_ratio() const {
        return delivered ? static_cast<double>(control_packets) / delivered : 0.0;
    }
};

std::string name(Protocol p) {
    if (p == Protocol::Flooding) return "AODV-like flooding";
    if (p == Protocol::Clustered) return "Clustered routing";
    return "Secure clustered routing";
}

std::vector<Node> initial_nodes(std::mt19937_64& rng) {
    std::uniform_real_distribution<double> jitter(-18.0, 18.0);
    std::uniform_real_distribution<double> speed(12.0, 28.0);
    std::vector<Node> nodes;
    nodes.reserve(kNodes);

    // Vehicles occupy two horizontal and two vertical road corridors.
    for (int i = 0; i < kVehicles; ++i) {
        Node n;
        if (i < 8) {
            n.x = 90.0 + i * 175.0 + jitter(rng);
            n.y = (i % 2 == 0 ? 610.0 : 810.0) + jitter(rng);
            n.vx = (i % 3 == 0 ? -1.0 : 1.0) * speed(rng);
        } else {
            n.x = (i % 2 == 0 ? 610.0 : 810.0) + jitter(rng);
            n.y = 100.0 + (i - 8) * 205.0 + jitter(rng);
            n.vy = (i % 3 == 0 ? -1.0 : 1.0) * speed(rng);
        }
        nodes.push_back(n);
    }

    const double rsu_positions[kRsus][2] = {
        {375.0, 610.0}, {1125.0, 810.0}, {610.0, 375.0}, {810.0, 1125.0}
    };
    for (const auto& pos : rsu_positions) {
        nodes.push_back(Node{pos[0], pos[1], 0.0, 0.0, true, -1});
    }
    return nodes;
}

void move_nodes(std::vector<Node>& nodes) {
    for (int i = 0; i < kVehicles; ++i) {
        auto& n = nodes[i];
        n.x += n.vx * kStep;
        n.y += n.vy * kStep;
        if (n.x < 40.0 || n.x > 1460.0) {
            n.vx = -n.vx;
            n.x = std::clamp(n.x, 40.0, 1460.0);
        }
        if (n.y < 40.0 || n.y > 1460.0) {
            n.vy = -n.vy;
            n.y = std::clamp(n.y, 40.0, 1460.0);
        }
    }
}

double distance(const Node& a, const Node& b) {
    return std::hypot(a.x - b.x, a.y - b.y);
}

void assign_clusters(std::vector<Node>& nodes) {
    for (int i = 0; i < kVehicles; ++i) {
        double best = std::numeric_limits<double>::max();
        for (int r = 0; r < kRsus; ++r) {
            const double d = distance(nodes[i], nodes[kVehicles + r]);
            if (d < best) {
                best = d;
                nodes[i].cluster = r;
            }
        }
    }
}

std::vector<std::vector<int>> graph(const std::vector<Node>& nodes) {
    std::vector<std::vector<int>> links(kNodes);
    for (int i = 0; i < kNodes; ++i) {
        for (int j = i + 1; j < kNodes; ++j) {
            if (distance(nodes[i], nodes[j]) <= kRange) {
                links[i].push_back(j);
                links[j].push_back(i);
            }
        }
    }
    return links;
}

struct Route {
    int hops{-1};
    int discovered{};
};

Route find_route(const std::vector<std::vector<int>>& links, int source, int destination) {
    std::vector<int> hops(kNodes, -1);
    std::queue<int> pending;
    pending.push(source);
    hops[source] = 0;
    int discovered = 0;
    while (!pending.empty()) {
        const int current = pending.front();
        pending.pop();
        ++discovered;
        if (current == destination) return {hops[current], discovered};
        for (int next : links[current]) {
            if (hops[next] == -1) {
                hops[next] = hops[current] + 1;
                pending.push(next);
            }
        }
    }
    return {-1, discovered};
}

Metrics run_once(Protocol protocol, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    auto nodes = initial_nodes(rng);
    std::uniform_int_distribution<int> vehicle(0, kVehicles - 1);
    std::uniform_real_distribution<double> chance(0.0, 1.0);
    Metrics result;

    // Nodes 3 and 11 represent revoked/malicious vehicles.
    const auto malicious = [](int id) { return id == 3 || id == 11; };

    const int steps = static_cast<int>(kDuration / kStep);
    for (int step = 0; step < steps; ++step) {
        move_nodes(nodes);
        assign_clusters(nodes);
        const auto links = graph(nodes);

        for (int burst = 0; burst < 8; ++burst) {
            int source = vehicle(rng);
            int destination = vehicle(rng);
            while (destination == source) destination = vehicle(rng);
            ++result.offered;

            const bool bad_packet = malicious(source) || chance(rng) < 0.025;
            if (protocol == Protocol::SecureClustered && bad_packet) {
                ++result.auth_drops;
                continue;
            }
            ++result.legitimate;

            const Route route = find_route(links, source, destination);
            if (route.hops < 0) {
                ++result.route_drops;
                continue;
            }

            int control = route.discovered;
            if (protocol != Protocol::Flooding) {
                // Cluster heads/RSUs scope discovery to the endpoint clusters.
                const bool same_cluster = nodes[source].cluster == nodes[destination].cluster;
                control = route.hops + (same_cluster ? 2 : 5);
            }
            result.control_packets += control;

            // A compact contention model: more route-control traffic raises the
            // probability of collision. Secure mode has small processing cost.
            const double collision = std::min(
                0.32,
                0.012 * route.hops + 0.0035 * control +
                    (protocol == Protocol::Flooding ? 0.055 : 0.018));
            if (chance(rng) < collision) {
                ++result.route_drops;
                continue;
            }

            ++result.delivered;
            const double auth_delay =
                protocol == Protocol::SecureClustered ? 0.00065 * route.hops : 0.0;
            const double queue_delay = 0.00022 * control;
            result.delay_sum += 0.0028 * route.hops + queue_delay + auth_delay;
        }
    }
    return result;
}

Metrics combine(const std::vector<Metrics>& runs) {
    Metrics total;
    for (const auto& m : runs) {
        total.offered += m.offered;
        total.legitimate += m.legitimate;
        total.delivered += m.delivered;
        total.auth_drops += m.auth_drops;
        total.route_drops += m.route_drops;
        total.control_packets += m.control_packets;
        total.delay_sum += m.delay_sum;
    }
    return total;
}

void write_header(std::ostream& out) {
    out << "protocol,offered,legitimate,delivered,auth_drops,route_drops,"
           "pdr_percent,delay_ms,throughput_kbps,control_packets,overhead_ratio\n";
}

void write_row(
    std::ostream& out, const std::string& protocol, const Metrics& m,
    double run_count = 1.0) {
    out << protocol << ',' << m.offered << ',' << m.legitimate << ',' << m.delivered
        << ',' << m.auth_drops << ',' << m.route_drops << ',' << std::fixed
        << std::setprecision(3) << m.pdr() << ',' << m.average_delay_ms() << ','
        << m.throughput_kbps() / run_count << ',' << m.control_packets << ','
        << m.overhead_ratio() << '\n';
}

}  // namespace

int main() {
    std::filesystem::create_directories("results");
    std::ofstream detailed("results/runs.csv");
    std::ofstream summary("results/summary.csv");
    if (!detailed || !summary) {
        std::cerr << "Unable to create result files\n";
        return 1;
    }
    detailed << "seed,";
    write_header(detailed);
    write_header(summary);

    const std::vector<Protocol> protocols = {
        Protocol::Flooding, Protocol::Clustered, Protocol::SecureClustered
    };
    for (Protocol protocol : protocols) {
        std::vector<Metrics> runs;
        for (std::uint64_t seed = 1; seed <= 10; ++seed) {
            const Metrics metrics = run_once(protocol, 20260724 + seed * 101);
            runs.push_back(metrics);
            detailed << seed << ',';
            write_row(detailed, name(protocol), metrics);
        }
        const Metrics total = combine(runs);
        write_row(summary, name(protocol), total, runs.size());
        std::cout << std::left << std::setw(27) << name(protocol)
                  << " PDR=" << std::setw(7) << std::fixed << std::setprecision(2)
                  << total.pdr() << "% delay=" << std::setw(7)
                  << total.average_delay_ms() << "ms throughput=" << std::setw(8)
                  << total.throughput_kbps() / runs.size()
                  << "kbps overhead=" << total.overhead_ratio() << '\n';
    }
    std::cout << "Results written to results/summary.csv and results/runs.csv\n";
}
