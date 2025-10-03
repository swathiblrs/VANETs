
// vanet_sim.cpp
#include <bits/stdc++.h>
using namespace std;

struct Node {
    int id;
    double x, y;         // position
    bool isRSU;          // true = Road Side Unit, false = Vehicle
};

class VANET {
    vector<Node> nodes;
    double commRange;

public:
    VANET(double range) : commRange(range) {}

    void addNode(int id, double x, double y, bool isRSU) {
        nodes.push_back({id, x, y, isRSU});
    }

    double distance(const Node &a, const Node &b) {
        return sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y));
    }

    vector<int> getNeighbors(int nodeId) {
        vector<int> neighbors;
        for (auto &n : nodes) {
            if (n.id != nodeId && distance(nodes[nodeId], n) <= commRange) {
                neighbors.push_back(n.id);
            }
        }
        return neighbors;
    }

    void sendMessage(int src, int dest) {
        cout << "Message from Node " << src << " to Node " << dest << endl;
        if (distance(nodes[src], nodes[dest]) <= commRange) {
            cout << "  ✅ Direct transmission possible." << endl;
        } else {
            cout << "  🔄 Multi-hop transmission required..." << endl;
            bfsRoute(src, dest);
        }
    }

    void bfsRoute(int src, int dest) {
        queue<int> q;
        map<int, int> parent;
        set<int> visited;

        q.push(src);
        visited.insert(src);
        parent[src] = -1;

        while (!q.empty()) {
            int cur = q.front(); q.pop();
            if (cur == dest) break;

            for (int nb : getNeighbors(cur)) {
                if (!visited.count(nb)) {
                    visited.insert(nb);
                    parent[nb] = cur;
                    q.push(nb);
                }
            }
        }

        if (!visited.count(dest)) {
            cout << "  ❌ No route found between Node " << src << " and Node " << dest << endl;
            return;
        }

        vector<int> path;
        for (int v = dest; v != -1; v = parent[v]) path.push_back(v);
        reverse(path.begin(), path.end());

        cout << "  ✅ Route found: ";
        for (int i = 0; i < path.size(); i++) {
            cout << path[i];
            if (i < path.size() - 1) cout << " -> ";
        }
        cout << endl;
    }
};

int main() {
    VANET vanet(50.0); // communication range = 50 units

    // Adding Vehicles (id, x, y, isRSU=false)
    vanet.addNode(0, 10, 10, false);
    vanet.addNode(1, 40, 10, false);
    vanet.addNode(2, 80, 10, false);
    vanet.addNode(3, 120, 10, false);

    // Adding Road Side Unit (id=4)
    vanet.addNode(4, 60, 10, true);

    cout << "\n🚗 VANET Simulation Started...\n" << endl;

    // Single-hop (within range)
    vanet.sendMessage(0, 1);

    // Multi-hop (needs relay)
    vanet.sendMessage(0, 3);

    // Vehicle to RSU
    vanet.sendMessage(2, 4);

    cout << "\n✅ Simulation Ended.\n";
    return 0;
}
