#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include <vector>
#include <string>

#include <openssl/rand.h>

#include "prover.h"
#include "proof.h"
#include "emp_prover.h"
#include "common.h"
#include "prover_sys.h"
#include "../utils/timer.h"
#include "circuit.h"

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
/*
static inline void SetWireNum(uint32_t *x, uint32_t wireNum) {
    *x = *x | (wireNum << 1);
}

static inline uint32_t GetWireNum(uint32_t x) {
    return x >> 1;
}*/
/*
static inline void SetBit(uint32_t *x, int bit, bool val) {
    *x = *x || (val << bit);
}*/

//template<typename IO>
void GenViewsHash(void (*f)(block[], block[], int), block *w, int wLen, vector<CircuitView *> &views, block *c, int outLen, uint8_t *seeds[], int numRands) {
//void GenViews(string circuitFile, block *w, int wLen, vector<CircuitView *> &views, block *c, int outLen, uint8_t *seeds[], int numRands) {
    uint64_t wShares[WIRES];
    uint64_t outShares[WIRES];
 	block* b = NULL;
 

    //FILE *f = fopen(circuitFile.c_str(), "r");
    //BristolFormat cf(f);
    //printf("n1=%d, n2=%d, n3=%d\n", cf.n1, cf.n2, cf.n3);
    ZKBooCircExecProver<AbandonIO> *ex = new ZKBooCircExecProver<AbandonIO>(seeds, w, wLen, numRands);
    CircuitExecution::circ_exec = ex;
    //setup_plain_prot(false, "");
    (*f)(c, w, wLen);
    //hash_in_circuit(c, w, wLen);
    //finalize_plain_prot();
    //cf.compute(c, w, b);
    for (int i = 0; i < 3; i++) {
        views.push_back(ex->view[i]);
    }
    // TODO cleanup
    delete ex;
    //fclose(f);
    
}

void GenViewsCtCircuit(block *mShares, int m_len, block *hashInShares, int in_len, block *hashOutShares, block *ctShares, block *keyShares, block *keyCommShares, block *keyRShares, __m128i iv, vector<CircuitView *> &views, block *out, uint8_t *seeds[], int numRands) {
    int wLen = m_len + 256 + 128 + m_len + 256 + 128 + in_len;
    block *w = new block[wLen];

    memset(w, 0xff, wLen * sizeof(block));
    memcpy((uint8_t *)w, mShares, m_len * sizeof(block));
    memcpy((uint8_t *)w + m_len * sizeof(block), hashOutShares, 256 * sizeof(block));
    memcpy((uint8_t *)w + (m_len + 256) * sizeof(block), ctShares, m_len * sizeof(block));
    memcpy((uint8_t *)w + (m_len + 256 + m_len) * sizeof(block), keyShares, 128 * sizeof(block));
    memcpy((uint8_t *)w + (m_len + 256 + m_len + 128) * sizeof(block), keyRShares, 128 * sizeof(block));
    memcpy((uint8_t *)w + (m_len + 256 + m_len + 128 + 128) * sizeof(block), keyCommShares, 256 * sizeof(block));
    memcpy((uint8_t *)w + (m_len + 256 + m_len + 128 + 128 + 256) * sizeof(block), hashInShares, in_len * sizeof(block));


    ZKBooCircExecProver<AbandonIO> *ex = new ZKBooCircExecProver<AbandonIO>(seeds, w, wLen, numRands);
    CircuitExecution::circ_exec = ex;
    check_ciphertext_circuit(hashOutShares, mShares, m_len, hashInShares, in_len, ctShares, iv, keyShares, keyCommShares, keyRShares, out);
    for (int i = 0; i < 3; i++) {
        views.push_back(ex->view[i]);
    }
    delete ex;
}

void CommitViews(vector<CircuitView *> &views, CircuitComm *comms) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        views[i]->Commit(comms[i]);
    }
}

void ShareInput(uint8_t *input, block *inputShares, int len, uint32_t *dst[], int offset) {
    uint32_t *indivShares[3];
    for (int i = 0; i < 3; i++) {
        indivShares[i] = (uint32_t *)malloc(len * sizeof(uint32_t));
    }
    memset(inputShares, 0, len * sizeof(block));
    for (int i = 0; i < len; i++) {
        // individual shares of bits
        RAND_bytes((uint8_t *)&indivShares[0][i], sizeof(uint32_t));
        RAND_bytes((uint8_t *)&indivShares[1][i], sizeof(uint32_t));
        indivShares[0][i] = indivShares[0][i] % 2;
        indivShares[1][i] = indivShares[1][i] % 2;
        indivShares[2][i] = indivShares[0][i] ^ indivShares[1][i] ^  GetBit(input[i/8], i%8);
        for (int j = 0; j < 3; j++) {
            SetWireNum(&indivShares[j][i], i + offset);
            memcpy(((uint8_t *)&inputShares[i]) + j * sizeof(uint32_t), (uint8_t *)&indivShares[j][i], sizeof(uint32_t));
            dst[j][i + offset] = indivShares[j][i];
        }
    }
}

void ProveCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, Proof &proof) {
    vector<CircuitView *>views;
    RandomOracle oracle; 

    proof.wLen = m_len + 256 + m_len + 128 + 128 + 256 + in_len;
    uint32_t *w_tmp[3];
    for (int i = 0; i < 3; i++) {
        w_tmp[i] = (uint32_t *)malloc(proof.wLen * sizeof(uint32_t));
    }
    block *out = new block[1];
    memset((void *)out, 0, sizeof(block));
    block *mShares = new block[m_len];
    ShareInput(m, mShares, m_len, w_tmp,  0);
    block *hashOutShares = new block[256];
    ShareInput(hashOut, hashOutShares, 256, w_tmp, m_len);
    block *ctShares = new block[m_len];
    ShareInput(ct, ctShares, m_len, w_tmp, m_len + 256);
    block *keyShares = new block[128];
    ShareInput(key, keyShares, 128, w_tmp, m_len + 256 + m_len);
    block *keyRShares = new block[128];
    ShareInput(keyR, keyRShares, 128, w_tmp, m_len + 256 + m_len + 128);
    block *keyCommShares = new block[256];
    ShareInput(keyComm, keyCommShares, 256, w_tmp, m_len + 256 + m_len + 128 + 128);
    block *hashInShares = new block[in_len];
    ShareInput(hashIn, hashInShares, in_len, w_tmp, m_len + 256 + m_len + 128 + 128 + 256);

    uint8_t *seeds[3];
    for (int i = 0; i < 3; i++) {
        seeds[i] = (uint8_t *)malloc(16);
        RAND_bytes(seeds[i], 16);
    }

    //INIT_TIMER;
    //START_TIMER;
    GenViewsCtCircuit(mShares, m_len, hashInShares, in_len, hashOutShares, ctShares, keyShares, keyCommShares, keyRShares, iv, views, out, seeds, numRands);
    //STOP_TIMER("Gen views");
    CommitViews(views, proof.comms);
    
    proof.idx = oracle.GetRand(proof.comms) % 3;
    fprintf(stderr, "zkboo: got idx = %d\n", proof.idx);
    proof.views[0] = views[proof.idx];
    proof.views[1] = views[(proof.idx + 1) % 3];
    proof.w[0] = w_tmp[proof.idx];
    proof.w[1] = w_tmp[(proof.idx + 1) % 3];
    // TODO run randomness tape on verifier
    proof.rands[0] = new RandomSource(seeds[proof.idx], numRands);
    proof.rands[1] = new RandomSource(seeds[(proof.idx+1)%3], numRands);
    //memcpy(proof.rands[0].seed, seeds[proof.idx], SHA256_DIGEST_LENGTH);
    //memcpy(proof.rands[1].seed, seeds[(proof.idx + 1) % 3], SHA256_DIGEST_LENGTH);

    proof.outShares[0] = (uint32_t *)malloc(sizeof(uint32_t));
    proof.outShares[1] = (uint32_t *)malloc(sizeof(uint32_t));
    bool b;
    memcpy(((uint8_t *)&proof.outShares[0][0]), ((uint8_t *)&out[0]) + proof.idx * sizeof(uint32_t), sizeof(uint32_t));
    memcpy(((uint8_t *)&proof.outShares[1][0]), ((uint8_t *)&out[0]) + ((proof.idx + 1) % 3) * sizeof(uint32_t), sizeof(uint32_t));
    uint32_t shares[3];
    for (int j = 0; j < 3; j++) {
        memcpy((uint8_t *)&shares[j], ((uint8_t *)&out[0]) + (sizeof(uint32_t) * j), sizeof(uint32_t));
    }
    b = (shares[0] + shares[1] + shares[2]) % 2;
    fprintf(stderr, "zkboo: OUTPUT: %d\n", b);
    //uint8_t *output_bytes = (uint8_t *)malloc(out_len / 8);
    /*from_bool(bs, output, out_len);
    printf("output bytes: ");
    for (int i = 0; i < out_len / 8; i++) {
        printf("%x", output[i]);
    }
    printf("\n");*/
}

// each block just contains one bit
void ProveHash(void (*f)(block[], block[], int), uint8_t *w, int in_len, int out_len, int numRands, Proof &proof, uint8_t *output) {
//void Prove(string circuitFile, uint8_t *w, int in_len, int out_len, int numRands, Proof &proof) {
    vector<CircuitView *> views;
    //int out_len = 256;
    block *out = new block[out_len];
    block *wShares = (block *)malloc(in_len * sizeof(block));
    memset((void *)out, 0, sizeof(block) * out_len);
    uint32_t *indivShares[3];
    for (int i = 0; i < 3; i++) {
        indivShares[i] = (uint32_t *)malloc(in_len * sizeof(uint32_t));
    }
    memset(wShares, 0, in_len * sizeof(block));
    for (int i = 0; i < in_len; i++) {
        // individual shares of bits
        RAND_bytes((uint8_t *)&indivShares[0][i], sizeof(uint32_t));
        RAND_bytes((uint8_t *)&indivShares[1][i], sizeof(uint32_t));
        indivShares[0][i] = indivShares[0][i] % 2;
        indivShares[1][i] = indivShares[1][i] % 2;
        indivShares[2][i] = indivShares[0][i] ^ indivShares[1][i] ^  GetBit(w[i/8], i%8);
        for (int j = 0; j < 3; j++) {
            SetWireNum(&indivShares[j][i], i);
            memcpy(((uint8_t *)&wShares[i]) + j * sizeof(uint32_t), (uint8_t *)&indivShares[j][i], sizeof(uint32_t));
        }
    }
    //currGate = 0;
    RandomOracle oracle;
    uint8_t *seeds[3];
    for (int i = 0; i < 3; i++) {
        seeds[i] = (uint8_t *)malloc(16);
        RAND_bytes(seeds[i], 16);
    }
    //INIT_TIMER;
    //START_TIMER;
    GenViewsHash(*f, wShares, in_len, views, out, 8, seeds, numRands);
    //GenViews(circuitFile, wShares, in_len, views, out, 8, seeds, numRands);
    //STOP_TIMER("gen views");
    //START_TIMER;
    CommitViews(views, proof.comms);
    //STOP_TIMER("commit");
    
    proof.idx = oracle.GetRand(proof.comms) % WIRES;
    proof.views[0] = views[proof.idx];
    proof.views[1] = views[(proof.idx + 1) % WIRES];
    // TODO run randomness tape on verifier
    proof.rands[0] = new RandomSource(seeds[proof.idx], numRands);
    proof.rands[1] = new RandomSource(seeds[(proof.idx+1)%3], numRands);
    //memcpy(proof.rands[0].seed, seeds[proof.idx], SHA256_DIGEST_LENGTH);
    //memcpy(proof.rands[1].seed, seeds[(proof.idx + 1) % 3], SHA256_DIGEST_LENGTH);

    proof.w[0] = indivShares[proof.idx];
    proof.w[1] = indivShares[(proof.idx + 1) % 3];
    proof.wLen = in_len;
    proof.outShares[0] = (uint32_t *)malloc(out_len * sizeof(uint32_t));
    proof.outShares[1] = (uint32_t *)malloc(out_len * sizeof(uint32_t));
    bool *bs = new bool[out_len];
    for (int i = 0; i < out_len; i++) {
        memcpy(((uint8_t *)&proof.outShares[0][i]), ((uint8_t *)&out[i]) + proof.idx * sizeof(uint32_t), sizeof(uint32_t));
        memcpy(((uint8_t *)&proof.outShares[1][i]), ((uint8_t *)&out[i]) + ((proof.idx + 1) % 3) * sizeof(uint32_t), sizeof(uint32_t));
        uint32_t shares[3];
        for (int j = 0; j < 3; j++) {
            memcpy((uint8_t *)&shares[j], ((uint8_t *)&out[i]) + (sizeof(uint32_t) * j), sizeof(uint32_t));
        }
        bs[i] = (shares[0] + shares[1] + shares[2]) % 2;
    }
    //uint8_t *output_bytes = (uint8_t *)malloc(out_len / 8);
    from_bool(bs, output, out_len);
    fprintf(stderr, "zkboo: output bytes: ");
    for (int i = 0; i < out_len / 8; i++) {
        fprintf(stderr, "%x", output[i]);
    }
    fprintf(stderr, "\n");
}

