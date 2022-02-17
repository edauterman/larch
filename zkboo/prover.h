#ifndef _PROVER_H_
#define _PROVER_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <vector>

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
        uint8_t GetRand(int gate);
        //uint8_t GetRand(int gate, int wireIdx);
};

class RandomOracle {
    public:
        uint8_t GetRand(CircuitComm *in);
};

class Proof {
    public:
        CircuitComm comms[3];
        CircuitView *views[2];
        RandomSource rands[2];
        uint8_t *w[2];
        uint8_t *outShares[2];
        uint8_t *out;
        int output;
        int idx;
};

class Prover {
    public:
        Prover();
        
        void AddConst(WireVal &in, uint8_t alpha, WireVal &out);
        void MultConst(WireVal &in, uint8_t alpha, WireVal &out);
        void AddShares(WireVal &in0, WireVal &in1, WireVal &out);
        void SubShares(WireVal &in0, WireVal &in1, WireVal &out);
        void MultShares(WireVal &in0, WireVal &in1, WireVal &out);

        uint64_t AddConst(uint64_t in, uint8_t alpha);
        uint64_t MultConst(uint64_t in, uint8_t alpha);
        uint64_t AddShares(uint64_t a0, uint64_t b0);
        uint64_t MultShares(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1);

        //void GenViews(CircuitSpec &spec, WireVal w[], CircuitViews &views, WireVal out[]);
        //void CommitViews(CircuitViews &views, CircuitComm *comms);
        //void Prove(CircuitSpec &spec, WireVal w[], Proof &proof);
    private:
        RandomOracle oracle;
        RandomSource rands[WIRES];
        int currGate;
};

#endif
