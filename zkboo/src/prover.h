#ifndef _PROVER_H_
#define _PROVER_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <vector>

#include "view.h"
#include "proof.h"

#define WIRES 3

using namespace std;

class Prover {
    public:
        Prover(uint8_t *seeds[], int numRands);
        
        void AddConst(uint32_t in[], uint8_t alpha, uint32_t out[]);
        void AddShares(uint32_t a[], uint32_t b[], uint32_t out[]);
        void MultShares(uint32_t a[], uint32_t b[], uint32_t out[]);

        int numAnds;
    private:
        RandomOracle oracle;
        RandomSource *rands[3];
        int currGate;
};


#endif
