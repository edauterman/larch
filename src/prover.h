#ifndef _PROVER_H_
#define _PROVER_H_

#include <vector>
#include <stdint.h>

#define WIRES 3

using namespace std;

class WireVal {
    public:
        uint8_t shares[WIRES];

        void Copy(WireVal &from);
};

class CircuitView {
    public:
        vector<uint8_t> wireShares;
};

class CircuitViews {
    public:
        vector<WireVal> wires;
        CircuitView GetView(int idx);
};

class CircuitSpec {
    public:
        // R1CS circuit spec
        uint8_t **A;
        uint8_t **B;
        uint8_t **C;
        int m;
        int n;
};

class CircuitComms {
    // 3 commitments
};

class RandomSource {
    public:
        uint8_t GetRand(int gate, int wireIdx);
};

class RandomOracle {
    public:
        uint8_t GetRand(CircuitComms &in);
};

class Proof {
    public:
        CircuitComms comms;
        CircuitView views[2];
        RandomSource rands[2];
        int output;
};

class Prover {
    public:
        void AddConst(WireVal &in, uint8_t alpha, WireVal &out);
        void MultConst(WireVal &in, uint8_t alpha, WireVal &out);
        void AddShares(WireVal &in0, WireVal &in1, WireVal &out);
        void SubShares(WireVal &in0, WireVal &in1, WireVal &out);
        void MultShares(WireVal &in0, WireVal &in1, WireVal &out);

        void GenViews(CircuitSpec &spec, WireVal w[], CircuitViews &views, WireVal out[]);
        void CommitViews(CircuitViews &views, CircuitComms &comms);

        void Prove(CircuitSpec &spec, WireVal w[], Proof &proof);
    private:
        RandomOracle oracle;
        RandomSource rands[WIRES];
        int currGate;
};

#endif
