// vanet_sim_auth.cpp
// VANET demo with hop-by-hop authentication using HMAC-SHA1.
// Build: g++ -std=c++17 -O2 vanet_sim_auth.cpp -o vanet_auth && ./vanet_auth

#include <bits/stdc++.h>
using namespace std;

/* ----------------------------- Minimal SHA1 ------------------------------ */
struct SHA1 {
    uint32_t h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
    vector<uint8_t> buf; uint64_t total=0;

    static uint32_t rol(uint32_t v, int b){ return (v<<b) | (v>>(32-b)); }

    void process_block(const uint8_t* p){
        uint32_t w[80];
        for(int i=0;i<16;i++) w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|(p[4*i+3]);
        for(int i=16;i<80;i++) w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f,k,temp;
        for(int i=0;i<80;i++){
            if(i<20){ f=(b&c)|((~b)&d); k=0x5A827999; }
            else if(i<40){ f=b^c^d; k=0x6ED9EBA1; }
            else if(i<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
            else { f=b^c^d; k=0xCA62C1D6; }
            temp = rol(a,5) + f + e + k + w[i];
            e=d; d=c; c=rol(b,30); b=a; a=temp;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e;
    }

    void update(const void* data, size_t len){
        const uint8_t* p = (const uint8_t*)data; total += len;
        if(!buf.empty()){
            size_t need = 64 - buf.size();
            size_t take = min(need, len);
            buf.insert(buf.end(), p, p+take); p+=take; len-=take;
            if(buf.size()==64){ process_block(buf.data()); buf.clear(); }
        }
        while(len>=64){ process_block(p); p+=64; len-=64; }
        if(len) buf.insert(buf.end(), p, p+len);
    }

    array<uint8_t,20> finalize(){
        uint64_t bits = total*8;
        update("\x80",1);
        uint8_t z=0;
        while((buf.size()%64)!=56) update(&z,1);
        uint8_t L[8];
        for(int i=0;i<8;i++) L[7-i]=(bits>>(8*i))&0xff;
        update(L,8);
        array<uint8_t,20> out{};
        uint32_t hs[5]={h0,h1,h2,h3,h4};
        for(int i=0;i<5;i++){
            out[4*i]= (hs[i]>>24)&0xff;
            out[4*i+1]=(hs[i]>>16)&0xff;
            out[4*i+2]=(hs[i]>>8)&0xff;
            out[4*i+3]= hs[i]&0xff;
        }
        return out;
    }
};

static string to_hex(const uint8_t* p, size_t n){
    static const char* H="0123456789abcdef";
    string s; s.reserve(2*n);
    for(size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xf]); }
    return s;
}

/* ----------------------------- HMAC-SHA1 -------------------------------- */
static string hmac_sha1(const string& key, const string& msg){
    const size_t block=64;
    string k = key;
    if(k.size()>block){
        SHA1 t; t.update(k.data(), k.size());
        auto d=t.finalize(); k.assign((char*)d.data(), d.size());
    }
    if(k.size()<block) k.append(block-k.size(), '\0');

    string o(block,'\0'), i(block,'\0');
    for(size_t n=0;n<block;n++){ o[n]=k[n]^0x5c; i[n]=k[n]^0x36; }

    SHA1 inner; inner.update(i.data(), i.size()); inner.update(msg.data(), msg.size());
    auto id = inner.finalize();

    SHA1 outer; outer.update(o.data(), o.size()); outer.update(id.data(), id.size());
    auto od = outer.finalize();

    return to_hex(od.data(), od.size());
}

/* ----------------------------- VANET Model ------------------------------ */
struct Pos { double x{0}, y{0}; };
static double dist2(const Pos& a, const Pos& b){ double dx=a.x-b.x, dy=a.y-b.y; return dx*dx+dy*dy; }

enum class NodeType { Vehicle, RSU };

struct Node {
    int id;
    NodeType type;
    Pos p;
    double vx{0}, vy{0};
    string key;
};

struct Message {
    int src, dst;
    int ttl{10};
    string payload;
    string mac;
    uint64_t nonce;
};

struct TrustedAuthority {
    unordered_map<int,string> secrets;
    void registerNode(int id, const string& k){ secrets[id]=k; }
    string getKey(int id) const {
        auto it=secrets.find(id); return (it==secrets.end()? string(): it->second);
    }
};

struct Vanet {
    vector<Node> nodes;
    double range{150.0}, range2{range*range};
    vector<vector<int>> adj;
    TrustedAuthority TA;
    mt19937_64 rng{42};

    // ✅ constructor so you can call Vanet R(…) in main
    Vanet(double r = 150.0) : range(r), range2(r*r) {}

    int addVehicle(Pos p, double vx, double vy, const string& key){
        int id=nodes.size();
        nodes.push_back(Node{id,NodeType::Vehicle,p,vx,vy,key});
        TA.registerNode(id,key);
        return id;
    }
    int addRSU(Pos p, const string& key){
        int id=nodes.size();
        nodes.push_back(Node{id,NodeType::RSU,p,0,0,key});
        TA.registerNode(id,key);
        return id;
    }

    void step(double dt, double W=800, double H=600){
        for(auto& n:nodes){
            if(n.type==NodeType::Vehicle){
                n.p.x+=n.vx*dt; n.p.y+=n.vy*dt;
                if(n.p.x<0){ n.p.x=0; n.vx=fabs(n.vx);}
                if(n.p.y<0){ n.p.y=0; n.vy=fabs(n.vy);}
                if(n.p.x>W){ n.p.x=W; n.vx=-fabs(n.vx);}
                if(n.p.y>H){ n.p.y=H; n.vy=-fabs(n.vy);}
            }
        }
        int n=nodes.size();
        adj.assign(n,{});
        for(int i=0;i<n;i++) for(int j=i+1;j<n;j++)
            if(dist2(nodes[i].p,nodes[j].p)<=range2){ adj[i].push_back(j); adj[j].push_back(i); }
    }

    vector<int> route(int s, int d, int maxHops=50){
        int n=nodes.size(); vector<int> par(n,-1); queue<int> q; q.push(s); par[s]=s;
        while(!q.empty()){
            int u=q.front(); q.pop(); if(u==d) break;
            for(int v:adj[u]) if(par[v]==-1){ par[v]=u; q.push(v); }
        }
        if(par[d]==-1) return {};
        vector<int> path; for(int v=d;;v=par[v]){ path.push_back(v); if(v==s) break; }
        reverse(path.begin(), path.end()); return path;
    }

    Message makeMessage(int src, int dst, string payload, int ttl=10){
        uniform_int_distribution<uint64_t> dist;
        Message m{src,dst,ttl,move(payload),{},dist(rng)};
        string key = TA.getKey(src);
        string meta = to_string(src)+"|"+to_string(dst)+"|"+to_string(ttl)+"|"+m.payload+"|"+to_string(m.nonce);
        m.mac = hmac_sha1(key, meta);
        return m;
    }

    bool verifyAtHop(const Message& m){
        string key = TA.getKey(m.src);
        string meta = to_string(m.src)+"|"+to_string(m.dst)+"|"+to_string(m.ttl)+"|"+m.payload+"|"+to_string(m.nonce);
        string expect = hmac_sha1(key, meta);
        return expect==m.mac;
    }

    bool deliver(Message m){
        auto direct = find(adj[m.src].begin(), adj[m.src].end(), m.dst)!=adj[m.src].end();
        vector<int> path = direct ? vector<int>{m.src,m.dst} : route(m.src,m.dst,m.ttl);
        if(path.empty()){ cout<<"[ROUTING FAIL] no path "<<m.src<<"->"<<m.dst<<"\n"; return false; }

        for(size_t i=0;i<path.size();++i){
            int cur = path[i];
            if(!verifyAtHop(m)){
                cout<<"[AUTH FAIL] hop "<<cur<<": message dropped (bad MAC)\n";
                return false;
            }
        }
        cout<<(path.size()==2?"[SINGLE-HOP] ":"[MULTI-HOP] ")
            <<"AUTH OK: delivered \""<<m.payload<<"\" "<<m.src<<"->"<<m.dst<<" via ";
        for(size_t i=0;i<path.size();++i){ cout<<path[i]<<(i+1<path.size()?" -> ":""); }
        cout<<" (hops="<<path.size()-1<<")\n";
        return true;
    }

    void printSnapshot(){
        cout<<"=== Snapshot ===\n";
        for(auto& n:nodes){
            cout<<"Node "<<n.id<<" ["<<(n.type==NodeType::Vehicle?"Vehicle":"RSU")
                <<"] pos=("<<fixed<<setprecision(1)<<n.p.x<<","<<n.p.y<<") links="<<adj[n.id].size()<<"\n";
        }
    }
};

int main(){
    Vanet sim(150.0);

    int rsuA = sim.addRSU({100,500},"key_rsuA");
    int rsuB = sim.addRSU({700,100},"key_rsuB");

    auto rnd = [](double a,double b){ return a + (b-a)*(rand()/(double)RAND_MAX); };
    srand(7);
    vector<int> V;
    for(int i=0;i<8;i++){
        Pos p{ rnd(50,750), rnd(50,550) };
        double vx=rnd(-40,40), vy=rnd(-40,40);
        V.push_back(sim.addVehicle(p,vx,vy,"veh_key_"+to_string(i)));
    }

    for(int t=0;t<4;t++){
        cout<<"\n--- t="<<t<<"s ---\n";
        sim.step(1.0);
        sim.printSnapshot();

        auto msg1 = sim.makeMessage(V[0], V[4], "V2V safety alert", 8);
        sim.deliver(msg1);

        auto msg2 = sim.makeMessage(V[2], rsuA, "Telemetry upload", 8);
        sim.deliver(msg2);

        auto bad = sim.makeMessage(V[1], rsuB, "Bogus packet", 8);
        bad.mac[0] = (bad.mac[0]=='a'?'b':'a'); // tamper MAC
        sim.deliver(bad);
    }
    return 0;
}