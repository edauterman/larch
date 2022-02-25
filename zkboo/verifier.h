#ifndef _VERIFIER_H_
#define _VERIFIER_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>

#include "view.h"
#include "prover.h"

#define WIRES 3

using namespace std;

class Verifier {
    public:
        Verifier(RandomSource rands[]);

        void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

    private:
        RandomSource rands[2];
        int currGate;
};

bool Verify(string circuitFile, Proof &proof);

#endif
