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

        void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

        int idx;

    private:
        RandomSource *rands[2];
        int currGate;
        int numAnds;
};

bool Verify(void (*f)(block[], block[], int), Proof &proof);
//bool Verify(string circuitFile, Proof &proof);

#endif
