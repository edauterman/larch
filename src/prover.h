#ifndef _PROVER_H_
#define _PROVER_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>

#include "view.h"

#define WIRES 3

using namespace std;

class CircuitSpec {
    public:
        // R1CS circuit spec
        uint8_t **A;
        uint8_t **B;
        uint8_t **C;
        int m;
        int n;
};

class RandomSource {
    public:
        uint8_t seed[SHA256_DIGEST_LENGTH];

        RandomSource();
        uint8_t GetRand(int gate, int wireIdx);
};

class RandomOracle {
    public:
        uint8_t GetRand(CircuitComm *in);
};

class Proof {
    public:
        CircuitComm comms[3];
        CircuitView views[2];
        RandomSource rands[2];
        uint8_t *w[2];
        int output;
        int idx;
};

class Prover {
    public:
        void AddConst(WireVal &in, uint8_t alpha, WireVal &out);
        void MultConst(WireVal &in, uint8_t alpha, WireVal &out);
        void AddShares(WireVal &in0, WireVal &in1, WireVal &out);
        void SubShares(WireVal &in0, WireVal &in1, WireVal &out);
        void MultShares(WireVal &in0, WireVal &in1, WireVal &out);

        void GenViews(CircuitSpec &spec, WireVal w[], CircuitViews &views, WireVal out[]);
        void CommitViews(CircuitViews &views, CircuitComm *comms);

        void Prove(CircuitSpec &spec, WireVal w[], Proof &proof);
    private:
        RandomOracle oracle;
        RandomSource rands[WIRES];
        int currGate;
};

#endif
