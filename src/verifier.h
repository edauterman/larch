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
        bool Verify(CircuitSpec &spec, Proof &proof);

    private:
        bool CheckAddConst(int wireIdx, uint8_t in0, uint8_t in1, uint8_t alpha, uint8_t out);
        bool CheckMultConst(uint8_t in0, uint8_t in1, uint8_t alpha, uint8_t out);
        bool CheckAddShares(uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out);
        bool CheckSubShares(uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out);
        bool CheckMultShares(int currGate, int wireIdx, RandomSource &rand0, RandomSource &rand1, uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out);
};

#endif
