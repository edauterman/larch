#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include <vector>
#include <string>
#include <thread>
#include <semaphore.h>

#include <openssl/rand.h>

#include "prover.h"
#include "proof.h"
#include "emp_prover.h"
#include "prover_sys.h"
#include "../utils/timer.h"
#include "../../crypto/src/params.h"
#include "circuit.h"

using namespace std;
using namespace emp;

void GenViewsCtCircuit(block *mShares, int m_len, block *hashInShares, int in_len, block *hashOutShares, block *ctShares, block *keyShares, block *keyCommShares, block *keyRShares, __m128i iv, vector<CircuitView *> &proverViews, block *out, uint8_t seeds[3][32][16], int numRands) {
    int wLen = m_len + 256 + 128 + m_len + 256 + 128 + in_len;
    block *w = (block*) aligned_alloc(16, sizeof(block) * wLen);

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
    check_ciphertext_circuit(ex, hashOutShares, mShares, m_len, hashInShares, in_len, ctShares, iv, keyShares, keyCommShares, keyRShares, out);
    for (int i = 0; i < 3; i++) {
        proverViews.push_back(ex->proverViews[i]);
    }

    free(w);
}

void CommitViews(vector<CircuitView *> &views, CircuitComm comms[3][32], uint8_t openings[3][32][16]) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 32; j++) {
            views[i]->Commit(comms[i][j], j, openings[i][j]);
        }
    }
}

void ShareInput(uint8_t *input, block *inputShares, int len, uint32_t *dst[], int offset) {
    uint32_t *indivShares[3];
    for (int i = 0; i < 3; i++) {
        indivShares[i] = (uint32_t *)malloc(len * sizeof(uint32_t));
    }
    memset(inputShares, 0, len * sizeof(block));
    RAND_bytes((uint8_t *)indivShares[0], len * sizeof(uint32_t));
    RAND_bytes((uint8_t *)indivShares[1], len * sizeof(uint32_t));
    for (int i = 0; i < len; i++) {
        // individual shares of bits
        uint32_t setval = GetBit((uint32_t)input[i/8], i%8) == 0 ? 0 : 0xffffffff;
        indivShares[2][i] = indivShares[0][i] ^ indivShares[1][i] ^ setval;
        for (int j = 0; j < 3; j++) {
            memcpy(((uint8_t *)&inputShares[i]) + j * sizeof(uint32_t), (uint8_t *)&indivShares[j][i], sizeof(uint32_t));
            dst[j][i + offset] = indivShares[j][i];
        }
    }

    for (int i = 0; i < 3; i++) {
        free(indivShares[i]);
    }
}

void FillVerifierView(vector<CircuitView *> &proverViews, CircuitView * verifierView, uint32_t *idx) {
    for (int i = 0; i < proverViews[0]->wires.size(); i++) {
        uint32_t val = 0;
        for (int j = 0; j < 32; j++) {
            SetBit(&val, j, GetBit(proverViews[(idx[j] + 1) % 3]->wires[i], j));
        }
        verifierView->wires.push_back(val);
    }
}

void ProveSerializeCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, uint8_t **proof_bytes, int *proof_len, sem_t *sema) {
    Proof p;
    ProveCtCircuit(m, m_len, hashIn, in_len, hashOut, ct, key, keyComm, keyR, iv, numRands, &p);
    *proof_bytes = p.Serialize(proof_len);
    sem_post(sema);
}

void ProveCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, Proof *proof) {
    vector<CircuitView *>verifierViews;
    vector<CircuitView *>proverViews;
    RandomOracle oracle; 
    uint8_t openings[3][32][16];
    //INIT_TIMER;
    //START_TIMER;

    proof->wLen = m_len + 256 + m_len + 128 + 128 + 256 + in_len;
    uint32_t *w_tmp[3];
    for (int i = 0; i < 3; i++) {
        w_tmp[i] = (uint32_t *)malloc(proof->wLen * sizeof(uint32_t));
    }
    block *out = (block*) aligned_alloc(16, sizeof(block) * 1);
    memset((void *)out, 0, sizeof(block));
    block *mShares = (block*) aligned_alloc(16, sizeof(block) * m_len);
    ShareInput(m, mShares, m_len, w_tmp,  0);
    block *hashOutShares = (block*) aligned_alloc(16, sizeof(block) * 256);
    ShareInput(hashOut, hashOutShares, 256, w_tmp, m_len);
    block *ctShares = (block*) aligned_alloc(16, sizeof(block) * m_len);
    ShareInput(ct, ctShares, m_len, w_tmp, m_len + 256);
    block *keyShares = (block*) aligned_alloc(16, sizeof(block) * 128);
    ShareInput(key, keyShares, 128, w_tmp, m_len + 256 + m_len);
    block *keyRShares = (block*) aligned_alloc(16, sizeof(block) * 128);
    ShareInput(keyR, keyRShares, 128, w_tmp, m_len + 256 + m_len + 128);
    block *keyCommShares = (block*) aligned_alloc(16, sizeof(block) * 256);
    ShareInput(keyComm, keyCommShares, 256, w_tmp, m_len + 256 + m_len + 128 + 128);
    block *hashInShares = (block*) aligned_alloc(16, sizeof(block) * in_len);
    ShareInput(hashIn, hashInShares, in_len, w_tmp, m_len + 256 + m_len + 128 + 128 + 256);

    uint8_t seeds[3][32][16];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 32; j++) {
            RAND_bytes(seeds[i][j], 16);
            RAND_bytes(openings[i][j], 16);
        }
    }
    //STOP_TIMER("before");

    //START_TIMER;
    GenViewsCtCircuit(mShares, m_len, hashInShares, in_len, hashOutShares, ctShares, keyShares, keyCommShares, keyRShares, iv, proverViews, out, seeds, numRands);
    //STOP_TIMER("gen views");
    //START_TIMER;
    CommitViews(proverViews, proof->comms, openings);
    //STOP_TIMER("comm");

    //START_TIMER;
    for (int i = 0; i < 32; i++) { 
        proof->idx[i] = oracle.GetRand(proof->comms[0][i], proof->comms[1][i], proof->comms[2][i]);
    }

    proof->view = new CircuitView();
    FillVerifierView(proverViews, proof->view, proof->idx);

    for (int i = 0; i < 2; i++) {
        proof->w[i] = (uint32_t *)malloc(proof->wLen * sizeof(uint32_t));
        for (int j = 0; j < proof->wLen; j++) {
            uint32_t val = 0;
            for (int k = 0; k < 32; k++) {
                SetBit(&val, k, GetBit(w_tmp[(proof->idx[k] + i) % 3][j], k));
            }
            proof->w[i][j] = val;
        }
        for (int j = 0; j < 32; j++) {
            memcpy(proof->openings[i][j], openings[(proof->idx[j] + i) % 3][j], 16);
        }
    }
    
    for (int i = 0; i < 3; i++) {
        proof->pubInShares[i] = (uint32_t *)malloc((m_len + 256 + 256) * sizeof(uint32_t));
        for (int j = 0; j < 256; j++) {
            memcpy((uint8_t *)&proof->pubInShares[i][j], ((uint8_t *)&hashOutShares[j]) + (i * sizeof(uint32_t)), sizeof(uint32_t));
        }
        for (int j = 0; j < 256; j++) {
            memcpy((uint8_t *)&proof->pubInShares[i][j + 256], ((uint8_t *)&keyCommShares[j]) + (i * sizeof(uint32_t)), sizeof(uint32_t));
        }
        for (int j = 0; j < m_len; j++) {
            memcpy((uint8_t *)&proof->pubInShares[i][j + 256 + 256], ((uint8_t *)&ctShares[j]) + (i * sizeof(uint32_t)), sizeof(uint32_t));
        }
    }

    for (int i = 0; i < 2; i++) {
        uint8_t seeds_tmp[32][16];
        for (int j = 0; j < 32; j++) {
            memcpy(seeds_tmp[j], seeds[(proof->idx[j] + i) % 3][j], 16);
        }
        proof->rands[i] = new RandomSource(seeds_tmp, numRands);
    }

    proof->outLen = 1;
    bool b;
    for (int i = 0; i < 3; i++) {
        proof->outShares[i] = (uint32_t *)malloc(sizeof(uint32_t));
        memcpy(((uint8_t *)&proof->outShares[i][0]), ((uint8_t *)&out[0]) + i * sizeof(uint32_t), sizeof(uint32_t));
    }
    uint32_t shares[3];
    for (int j = 0; j < 3; j++) {
        memcpy((uint8_t *)&shares[j], ((uint8_t *)&out[0]) + (sizeof(uint32_t) * j), sizeof(uint32_t));
    }
    b = (shares[0] + shares[1] + shares[2]) % 2;
    proof->out = (uint8_t *)malloc(1);
    proof->out[0] = b;

    for (int i = 0; i < 3; i++) {
        free(w_tmp[i]);
    }

    delete CircuitExecution::circ_exec;
    CircuitExecution::circ_exec = nullptr;
    free(out);
    free(mShares);
    free(hashOutShares);
    free(ctShares);
    free(keyShares);
    free(keyRShares);
    free(keyCommShares);
    free(hashInShares);
    //STOP_TIMER("whole thingy");
}

