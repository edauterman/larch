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

Prover::Prover() {
    currGate = 0;
}

void Prover::AddConst(WireVal &in, uint8_t alpha, WireVal &out) {
    out.Copy(in);
    out.shares[0] += alpha % 2;
    currGate++;
}

uint64_t Prover::AddConst(const uint64_t in, uint8_t alpha) {
    currGate++;
    return (in + alpha) % 2;
}

void Prover::MultConst(WireVal &in, uint8_t alpha, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = alpha * in.shares[i];
        out.shares[i] %= 2;
    }
    currGate++;
}

uint64_t Prover::MultConst(uint64_t in, uint8_t alpha) {
    currGate++;
    return (in * alpha) % 2;
}

void Prover::AddShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = in0.shares[i] + in1.shares[i];
        out.shares[i] %= 2;
    }
    currGate++;
}

uint64_t Prover::AddShares(uint64_t a0, uint64_t b0) {
    currGate++;
    printf("add shares\n");
    return (a0 + b0) % 2;
}

void Prover::SubShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        int diff = in0.shares[i] > in1.shares[i] ? in0.shares[i] - in1.shares[i] : in1.shares[i] - in0.shares[i];
        //out.shares[i] = in0.shares[i] - in1.shares[i];
        out.shares[i] = diff % 2;
    }
    currGate++;
}

void Prover::MultShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = (in0.shares[i] * in1.shares[i]) + 
                (in0.shares[(i + 1) % WIRES] * in1.shares[i]) + 
                (in0.shares[i] * in1.shares[(i + 1) % WIRES]) +
                rands[i].GetRand(currGate) - rands[(i + 1) % WIRES].GetRand(currGate);
        out.shares[i] %= 2;
    }
    currGate++;
}

uint64_t Prover::MultShares(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1) {
    currGate++;
    printf("mult shares\n");
    // TODO: need to make sure rands are correctly configured across runs
    return ((a0 * b0) + (a1 * b0) + (a0 * b1) + rands[0].GetRand(currGate) - rands[1].GetRand(currGate)) % 2;
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

