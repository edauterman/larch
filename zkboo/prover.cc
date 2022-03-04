#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include <vector>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "prover.h"
#include "common.h"

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

RandomSource::RandomSource(uint8_t *in_seed, int numRands) {
    memcpy(seed, in_seed, 16);
    //RAND_bytes(seed, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    uint8_t iv[16];
    uint8_t pt[16];
    memset(iv, 0, 16);
    memset(pt, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, iv);
    int len;
    randomness = (uint8_t *)malloc(numRands / 8 + 16);
    for (int i = 0; i < numRands / (8 * 16) + 1; i++) {
        EVP_EncryptUpdate(ctx, &randomness[i * 16], &len, pt, 16);
    }
    EVP_CIPHER_CTX_free(ctx);
}

uint8_t RandomSource::GetRand(int gate) {
    return GetBit(randomness[gate/8], gate%8);
    /*return 1;
    int buf[2 + SHA256_DIGEST_LENGTH / sizeof(int)];
    buf[0] = gate;
    //buf[1] = wireIdx % 3;
    memcpy((uint8_t *)(buf + 1), seed, SHA256_DIGEST_LENGTH);
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), (uint8_t *)buf, sizeof(int) + SHA256_DIGEST_LENGTH);
    return (out) % 2;*/
}

uint8_t RandomOracle::GetRand(CircuitComm *in) {
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), in->digest, SHA256_DIGEST_LENGTH);
    return out;
}

Prover::Prover(uint8_t *seeds[], int numRands) {
    currGate = 0;
    numAnds = 0;
    for (int i = 0; i < 3; i++) {
        rands[i] = new RandomSource(seeds[i], numRands);
        //memcpy(rands[i].seed, seeds[i], SHA256_DIGEST_LENGTH);
    }
}

void Prover::AddConst(uint32_t a[], uint8_t alpha, uint32_t out[]) {
    currGate++;
    int bit = 0;
    for (int i = 0; i < 3; i++) {
        out[i] = 0;
        bool aBit = GetBit(a[i], bit);
        bool res = i == 0 ? (aBit + alpha) % 2 : aBit;
        SetBit(&out[i], bit, res);
    }
}

void Prover::AddShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    int bit = 0;
    for (int i = 0; i < 3; i++) {
        out[i] = 0;
        SetBit(&out[i], bit, ((a[i] & 1) + (b[i] & 1)) % 2);
    }
}

void Prover::MultShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    int bit = 0;    
    for (int i = 0; i < 3; i++) {
        out[i] = 0;
        bool a0Bit = a[i] & 1;
        bool a1Bit = a[(i+1)%3] & 1;
        bool b0Bit = b[i] & 1;
        bool b1Bit = b[(i+1)%3] & 1;
        bool res = ((a0Bit * b0Bit) + (a1Bit * b0Bit) + (a0Bit * b1Bit)) % 2;
               // + rands[i]->GetRand(numAnds) - rands[(i+1)%3]->GetRand(numAnds)) % 2;
        SetBit(&out[i], bit, res);
    }
    numAnds++;
}

/*
// w of length n
void Prover::GenViews(CircuitSpec &spec, WireVal w[], CircuitViews &views, WireVal out[]) {
    WireVal A[spec.m];
    WireVal B[spec.m];
    WireVal C[spec.m];
    // TODO set to 0s if not init?
    for (int i = 0; i < spec.m; i++) {
        for (int j = 0; j < WIRES; j++) {
            A[i].shares[j] = 0;
            B[i].shares[j] = 0;
            C[i].shares[j] = 0;
        }
        for (int j = 0; j < spec.n; j++) {
            WireVal tmp;
            MultConst(w[j], spec.A[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, A[i], A[i]);
            views.wires.push_back(A[i]);
            MultConst(w[j], spec.B[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, B[i], B[i]);
            views.wires.push_back(B[i]);
            MultConst(w[j], spec.C[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, C[i], C[i]);
            views.wires.push_back(C[i]);
        }
        // A.w * B.w - C.w ?= 0
        MultShares(A[i], B[i], out[i]);
        views.wires.push_back(out[i]);
        SubShares(out[i], C[i], out[i]);
        views.wires.push_back(out[i]);
    }

    // Run adds and mults based on R1CS
}
*/

