#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include <vector>

#include <openssl/rand.h>

#include "prover.h"
#include "common.h"

using namespace std;
using namespace emp;

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)(x & (1 << bit));
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    *x = *x || (val << bit);
}

RandomSource::RandomSource() {
    RAND_bytes(seed, SHA256_DIGEST_LENGTH);
}

uint8_t RandomSource::GetRand(int gate) {
    int buf[2 + SHA256_DIGEST_LENGTH / sizeof(int)];
    buf[0] = gate;
    //buf[1] = wireIdx % 3;
    memcpy((uint8_t *)(buf + 1), seed, SHA256_DIGEST_LENGTH);
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), (uint8_t *)buf, sizeof(int) + SHA256_DIGEST_LENGTH);
    return (out) % 2;
}

uint8_t RandomOracle::GetRand(CircuitComm *in) {
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), in->digest, SHA256_DIGEST_LENGTH);
    return out;
}

Prover::Prover(uint8_t *seeds[]) {
    currGate = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(rands[i].seed, seeds[i], SHA256_DIGEST_LENGTH);
    }
}

void Prover::AddConst(uint32_t a[], uint8_t alpha, uint32_t out[]) {
    currGate++;
    for (int bit = 0; bit < 1; bit++) {
    //for (int bit = 0; bit < 32; bit++) {
        for (int i = 0; i < 3; i++) {
            bool aBit = GetBit(a[i], bit);
            bool res = i == 0 ? (aBit + alpha) % 2 : aBit;
            SetBit(&out[i], bit, res);
        }
    }
}

void Prover::AddShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    for (int bit = 0; bit < 1; bit++) {
    //for (int bit = 0; bit < 32; bit++) {
        for (int i = 0; i < 3; i++) {
            bool aBit = GetBit(a[i], bit);
            bool bBit = GetBit(b[i], bit);
            SetBit(&out[i], bit, (aBit + bBit) % 2);
        }
    }
}

void Prover::MultShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    for (int bit = 0; bit < 1; bit++) {
    //for (int bit = 0; bit < 32; bit++) {
        for (int i = 0; i < 3; i++) {
            bool a0Bit = GetBit(a[i], bit);
            bool a1Bit = GetBit(a[(i+1)%3], bit);
            bool b0Bit = GetBit(b[i], bit);
            bool b1Bit = GetBit(b[(i+1)%3], bit);
            bool res = ((a0Bit * b0Bit) + (a1Bit * b0Bit) + (a0Bit * b1Bit) + rands[i].GetRand(currGate) - rands[(i+1)%3].GetRand(currGate)) % 2;
            SetBit(&out[i], bit, res);
        }
    }
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

