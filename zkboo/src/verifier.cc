#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#include "verifier.h"
#include "prover.h"
#include "proof.h"
#include "view.h"
#include "circuit.h"
#include "emp_verifier.h"
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

void AssembleShares(uint32_t *in0, uint32_t *in1, uint32_t *in2, uint8_t *out, int num_blocks) {
    bool *bs = new bool[num_blocks];
    for (int i = 0; i < num_blocks; i++) {
        /*for (int j = 0; j < 3; j++) {
            memcpy((uint8_t *)&shares[j], ((uint8_t *)&in[i]) + (j * sizeof(uint32_t)), sizeof(uint32_t));
            //memcpy((uint8_t *)&shares[j], ((uint8_t *)&in[i]) + (j * sizeof(uint32_t)), sizeof(uint32_t));
        }*/
        bs[i] = (in0[i] + in1[i] + in2[i]) % 2;
    }
    from_bool(bs, out, num_blocks);
}

//bool VerifyCtCircuit(Proof &proof, __m128i iv, int m_len, int in_len) {
bool VerifyCtCircuit(Proof &proof, __m128i iv, int m_len, int in_len, uint8_t * hashOutRaw, uint8_t *keyCommRaw, uint8_t *ctRaw) {
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

    //int m_len = (proof.wLen - 256 - 128 - 128 - 256) / 2;
    block *m = new block[m_len];
    block *hashOut = new block[256];
    block *ct = new block[m_len];
    block *key = new block[128];
    block *keyR = new block[128];
    block *keyComm = new block[256];
    block *hashIn = new block[in_len];
    block *out = new block[1];

    // TODO: check hashOut, keyComm, and ct

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&m[i], (uint8_t *)&proof.w[0][i], sizeof(uint32_t));
        memcpy((uint8_t *)&m[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i], sizeof(uint32_t));
    }

    for (int i = 0; i < 256; i++) {
        memcpy((uint8_t *)&hashOut[i], (uint8_t *)&proof.w[0][i + m_len], sizeof(uint32_t));
        memcpy((uint8_t *)&hashOut[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len], sizeof(uint32_t));
        printf("hash out %d/256\n", i);
        for (int j = 0; j < 2; j++) {
            if (memcmp(((uint8_t *)&hashOut[i]) + (j * sizeof(uint32_t)), (uint8_t *)&proof.pubInShares[(j + proof.idx) % 3][i], sizeof(uint32_t)) != 0) return false;
        }
    }

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&ct[i], (uint8_t *)&proof.w[0][i + m_len + 256], sizeof(uint32_t));
        memcpy((uint8_t *)&ct[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256], sizeof(uint32_t));
        printf("ct %d/32\n", i);
        for (int j = 0; j < 2; j++) {
            if (memcmp(((uint8_t *)&ct[i]) + (j * sizeof(uint32_t)), (uint8_t *)&proof.pubInShares[(j + proof.idx) % 3][i + 256 + 256], sizeof(uint32_t)) != 0) return false;
        }
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
        printf("keyComm %d/256\n", i);
        for (int j = 0; j < 2; j++) {
            if (memcmp(((uint8_t *)&keyComm[i]) + (j * sizeof(uint32_t)), (uint8_t *)&proof.pubInShares[(j + proof.idx) % 3][i + 256], sizeof(uint32_t)) != 0) return false;
        }
    }

    for (int i = 0; i < in_len; i++) {
        memcpy((uint8_t *)&hashIn[i], (uint8_t *)&proof.w[0][i + m_len + 256 + m_len + 128 + 128 + 256], sizeof(uint32_t));
        memcpy((uint8_t *)&hashIn[i] + sizeof(uint32_t), (uint8_t *)&proof.w[1][i + m_len + 256 + m_len + 128 + 128 + 256], sizeof(uint32_t));
    }
    
    memcpy((uint8_t *)&out[0], (uint8_t *)&proof.outShares[proof.idx][0], sizeof(uint32_t));
    memcpy((uint8_t *)&out[0] + sizeof(uint32_t), (uint8_t *)&proof.outShares[(proof.idx + 1) % 3][0], sizeof(uint32_t));

    printf("going to assemble\n");
    uint8_t *hashOutTest = (uint8_t *)malloc(256 / 8);
    uint8_t *keyCommTest = (uint8_t *)malloc(256 / 8);
    uint8_t *ctTest = (uint8_t *)malloc(m_len / 8);
    AssembleShares(proof.pubInShares[0], proof.pubInShares[1], proof.pubInShares[2], hashOutTest, 256);
    AssembleShares(proof.pubInShares[0] + 256, proof.pubInShares[1] + 256, proof.pubInShares[2] + 256, keyCommTest, 256);
    AssembleShares(proof.pubInShares[0] + 512, proof.pubInShares[1] + 512, proof.pubInShares[2] + 512, ctTest, m_len);
    printf("going to check\n");
    if (memcmp(hashOutTest, hashOutRaw, 256 / 8) != 0) {
        return false;
    }
    printf("past hash out\n");
    if (memcmp(keyCommTest, keyCommRaw, 256 / 8) != 0) {
        return false;
    }
    printf("past key comm\n");
    if (memcmp(ctTest, ctRaw, m_len / 8) != 0) {
        return false;
    }
    printf("past ct\n");
    uint32_t outTest = (proof.outShares[0][0] + proof.outShares[1][0] + proof.outShares[2][0]) % 2;
    printf("outTest = %d\n", outTest);
    if (((proof.outShares[0][0] + proof.outShares[1][0] + proof.outShares[2][0]) % 2) != 1) {
        return false;
    }
    printf("output good\n");
    printf("did all input and output checks, about to run verifier\n");


    ZKBooCircExecVerifier<AbandonIO> *ex = new ZKBooCircExecVerifier<AbandonIO>(proof.rands, proof.views, proof.wLen, proof.idx);
    CircuitExecution::circ_exec = ex;
    check_ciphertext_circuit(hashOut, m, m_len, hashIn, in_len, ct, iv, key, keyComm, keyR, out);
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
