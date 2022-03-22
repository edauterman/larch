#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#include "verifier.h"
#include "prover.h"
#include "common.h"
#include "view.h"
#include "circuit.h"
#include "emp_verifier.h"

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

// QUESTION: should we just be checking out0???? or is it checking that both inputs used correctly????

Verifier::Verifier(RandomSource *in_rands[], int in_idx) {
    rands[0] = in_rands[0];
    rands[1] = in_rands[1];
    currGate = 0;
    idx = in_idx;
    numAnds = 0;
}

void Verifier::AddConst(uint32_t a[], uint8_t alpha, uint32_t out[]) {
    currGate++;

    for (int i = 0; i < 1; i++) {
        out[i] = 0;
        bool aBit = a[i] & 1;
        bool res = idx + i == 0 ? (aBit + alpha) % 2 : aBit;
        SetBit(&out[i], 0, res);
    }
}

void Verifier::AddShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    for (int i = 0; i < 1; i++) {
        out[i] = 0;
        SetBit(&out[i], 0, ((a[i] & 1) + (b[i] & 1)) % 2);
    }
}

void Verifier::MultShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    for (int i = 0; i < 1; i++) {
        out[i] = 0;
        bool a0Bit = a[i] & 1;
        bool a1Bit = a[i+1] & 1;
        bool b0Bit = b[i] & 1;
        bool b1Bit = b[i+1] & 1;
        bool res = ((a0Bit * b0Bit) + (a1Bit * b0Bit) + (a0Bit * b1Bit)
                + rands[i]->GetRand(numAnds) - rands[(i+1)]->GetRand(numAnds)) % 2;
        SetBit(&out[i], 0, res);
    }
    numAnds++;
}

bool VerifyCtCircuit(Proof &proof, __m128i iv) {
    CircuitComm c0, c1;
    proof.views[0]->Commit(c0);
    proof.views[1]->Commit(c1);
    if (memcmp(c0.digest, proof.comms[proof.idx].digest, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "zkboo: commit for v0 failed\n");
        return false;
    }

    if (memcmp(c1.digest, proof.comms[(proof.idx + 1) % WIRES].digest, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "zkboo: commit for v1 failed\n");
        return false;
    }

    // Need to check that views chosen randomly correctly?
    RandomOracle oracle;
    uint8_t idx_check = oracle.GetRand(proof.comms) % WIRES;
    if (proof.idx != idx_check) {
        return false;
    }

    int m_len = (proof.wLen - 256 - 128 - 128 - 256) / 2;
    block *m = new block[m_len];
    block *hashOut = new block[256];
    block *ct = new block[m_len];
    block *key = new block[128];
    block *keyR = new block[128];
    block *keyComm = new block[256];
    block *out = new block[1];

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&m[i], (uint8_t *)&proof.w[0][i], sizeof(uint32_t));
        memcpy((uint8_t *)&m[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i], sizeof(uint32_t));
    }

    for (int i = 0; i < 256; i++) {
        memcpy((uint8_t *)&hashOut[i], (uint8_t *)&proof.w[0][i + m_len], sizeof(uint32_t));
        memcpy((uint8_t *)&hashOut[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len], sizeof(uint32_t));
    }

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&ct[i], (uint8_t *)&proof.w[0][i + m_len + 256], sizeof(uint32_t));
        memcpy((uint8_t *)&ct[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256], sizeof(uint32_t));
    }

    for (int i = 0; i < 128; i++) {
        memcpy((uint8_t *)&key[i], (uint8_t *)&proof.w[0][i + m_len + 256 + m_len], sizeof(uint32_t));
        memcpy((uint8_t *)&key[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256 + m_len], sizeof(uint32_t));
    }

    for (int i = 0; i < 128; i++) {
        memcpy((uint8_t *)&keyR[i], (uint8_t *)&proof.w[0][i + m_len + 256 + m_len + 128], sizeof(uint32_t));
        memcpy((uint8_t *)&keyR[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256 + m_len + 128], sizeof(uint32_t));
    }

    for (int i = 0; i < 256; i++) {
        memcpy((uint8_t *)&keyComm[i], (uint8_t *)&proof.w[0][i + m_len + 256 + m_len + 128 + 128], sizeof(uint32_t));
        memcpy((uint8_t *)&keyComm[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256 + m_len + 128 + 128], sizeof(uint32_t));
    }

    ZKBooCircExecVerifier<AbandonIO> *ex = new ZKBooCircExecVerifier<AbandonIO>(proof.rands, proof.views, proof.wLen, proof.idx);
    CircuitExecution::circ_exec = ex;
    check_ciphertext_circuit(hashOut, m, m_len, ct, iv, key, keyComm, keyR, out);
    if (ex->verified) {
        return true;
    } else {
        return false;
    }

    // TODO check output lines up
    
    return true;
    
}

bool VerifyHash(void (*f)(block[], block[], int), Proof &proof) {
    CircuitComm c0, c1;
    proof.views[0]->Commit(c0);
    proof.views[1]->Commit(c1);
    if (memcmp(c0.digest, proof.comms[proof.idx].digest, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "zkboo: commit for v0 failed\n");
        return false;
    }

    if (memcmp(c1.digest, proof.comms[(proof.idx + 1) % WIRES].digest, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "zkboo: commit for v1 failed\n");
        return false;
    }

    // Need to check that views chosen randomly correctly?
    RandomOracle oracle;
    uint8_t idx_check = oracle.GetRand(proof.comms) % WIRES;
    if (proof.idx != idx_check) {
        return false;
    }

    int in_len = proof.wLen;
    block *w = new block[in_len];
    block *b = NULL;
    block *out = new block[256];

    for (int i = 0; i < in_len; i++) {
        memcpy((uint8_t *)&w[i], (uint8_t *)&proof.w[0][i], sizeof(uint32_t));
        memcpy((uint8_t *)&w[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i], sizeof(uint32_t));
    }

    //FILE *f = fopen(circuitFile.c_str(), "r");
    //BristolFormat cf(f);
    ZKBooCircExecVerifier<AbandonIO> *ex = new ZKBooCircExecVerifier<AbandonIO>(proof.rands, proof.views, in_len, proof.idx);
    CircuitExecution::circ_exec = ex;
    (*f)(out, w, in_len);
    //hash_in_circuit(out, w, in_len);
    //cf.compute(out, w, b);
    if (ex->verified) {
        return true;
    } else {
        return false;
    }

    // TODO check output lines up
    
    return true;
    
}
