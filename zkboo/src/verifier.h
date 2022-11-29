#ifndef _VERIFIER_H_
#define _VERIFIER_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <emp-tool/emp-tool.h>
#include "view.h"
#include "prover.h"

#define WIRES 3

using namespace std;
using namespace emp;

class Verifier {
    public:
        Verifier(RandomSource *rands[], uint32_t *idx);

        inline void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        inline void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        inline void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

        uint32_t idx[32];

    private:
        RandomSource *rands[2];
        uint32_t one_mask[2];
        int currGate;
        int numAnds;
};

bool VerifyDeserializeCtCircuit(uint8_t *proof_bytes, int numRands, __m128i iv, int m_len, int in_len, uint8_t * hashOutRaw, uint8_t *keyCommRaw, uint8_t *ctRaw, bool *ret);
bool VerifyCtCircuit(Proof *proof, __m128i iv, int m_len, int in_len, uint8_t *hashOutRaw, uint8_t *keyCommRaw, uint8_t *ctRaw, bool *ret);

#endif
