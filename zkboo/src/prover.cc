#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include <vector>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "prover.h"
#include "proof.h"
#include "../../crypto/params.h"

using namespace std;
using namespace emp;


static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    if (val == 0) {    
        *x = *x & (val << bit);
    } else {
        *x = *x | (val << bit);
    }
}


Prover::Prover(uint8_t seeds[3][32][16], int numRands) {
    currGate = 0;
    numAnds = 0;
    for (int i = 0; i < 3; i++) {
        rands[i] = new RandomSource(seeds[i], numRands);
        //memcpy(rands[i].seed, seeds[i], SHA256_DIGEST_LENGTH);
    }
    //id = rand() % 100;
}

void Prover::AddConst(uint32_t a[], uint8_t alpha, uint32_t out[]) {
    currGate++;
    int bit = 0;
    uint32_t setalpha = (alpha == 0) ? 0 : 0xffffffff;
    for (int i = 0; i < 3; i++) {
        //bool aBit = GetBit(a[i], bit);
        //bool res = i == 0 ? (aBit + alpha) % 2 : aBit;
        //SetBit(&out[i], bit, res);
        out[i] = 0xffffffff ^ a[i]; 
        //out[i] = (i == 0) ? a[i] ^ setalpha : a[i];
    }
}

void Prover::AddShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    int bit = 0;
    for (int i = 0; i < 3; i++) {
        out[i] = a[i] ^ b[i];
        //SetBit(&out[i], bit, ((a[i] & 1) + (b[i] & 1)) % 2);
    }
}

void Prover::MultShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    int bit = 0; 
    uint32_t masks[3];
    for (int i = 0; i < 3; i++) {
        masks[i] = 0;
        for (int j = 0; j < 32; j++) {
            masks[i] = masks[i] | (rands[i]->GetRand(j, numAnds) << j);
        }
    }   
    for (int i = 0; i < 3; i++) {
        /*out[i] = 0;
        bool a0Bit = a[i] & 1;
        bool a1Bit = a[(i+1)%3] & 1;
        bool b0Bit = b[i] & 1;
        bool b1Bit = b[(i+1)%3] & 1;
        bool res = ((a0Bit * b0Bit) + (a1Bit * b0Bit) + (a0Bit * b1Bit)
                + rands[i]->GetRand(numAnds) - rands[(i+1)%3]->GetRand(numAnds)) % 2;
        SetBit(&out[i], bit, res);*/
        out[i] = ((a[i] & b[i]) ^ (a[(i+1)%3] & b[i]) ^ (a[i] & b[(i+1)%3])
                ^ masks[i] ^ masks[(i+1)%3]);
                //^ rands[i]->GetRand(numAnds) ^ (rands[(i+1)%3]->GetRand(numAnds)));
    }
    numAnds++;
}

