#ifndef _PROOF_H_
#define _PROOF_H_

#include "view.h"

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
        uint32_t wLen;
        uint32_t *outShares[2];
        uint8_t *out;
        uint32_t outLen;
        uint32_t idx;

        uint8_t *Serialize(int *out_len);
        void Deserialize(uint8_t *buf, int numRands);
    private:
        void SerializeInt32(uint32_t x, uint8_t **buf);
        uint32_t DeserializeInt32(uint8_t **buf);
};

#endif
