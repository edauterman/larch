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
        uint8_t seed[16];
        uint8_t *randomness;

        RandomSource(uint8_t *seed, int numRands);
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
        RandomSource *rands[2];
        uint32_t *w[2];
        int wLen;
        uint32_t *outShares[2];
        uint8_t *out;
        int output;
        int idx;
};

class Prover {
    public:
        Prover(uint8_t *seeds[], int numRands);
        
        void AddConst(WireVal &in, uint8_t alpha, WireVal &out);
        void MultConst(WireVal &in, uint8_t alpha, WireVal &out);
        void AddShares(WireVal &in0, WireVal &in1, WireVal &out);
        void SubShares(WireVal &in0, WireVal &in1, WireVal &out);
        void MultShares(WireVal &in0, WireVal &in1, WireVal &out);

        void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

        //void GenViews(CircuitSpec &spec, WireVal w[], CircuitViews &views, WireVal out[]);
        //void CommitViews(CircuitViews &views, CircuitComm *comms);
        //void Prove(CircuitSpec &spec, WireVal w[], Proof &proof);
        int numAnds;
    private:
        RandomOracle oracle;
        RandomSource *rands[3];
        int currGate;
};


#endif
