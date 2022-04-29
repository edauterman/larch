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
        Verifier(RandomSource *rands[], int idx);

        inline void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        inline void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        inline void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

        int idx;

    private:
        RandomSource *rands[2];
        int currGate;
        int numAnds;
};

bool VerifyHash(void (*f)(block[], block[], int), Proof &proof);
bool VerifyCtCircuit(Proof &proof, __m128i iv, int m_len, int in_len, uint8_t *hashOutRaw, uint8_t *keyCommRaw, uint8_t *ctRaw);

#endif
