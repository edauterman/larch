#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include <vector>
#include <string>
#include <thread>

#include <openssl/rand.h>

#include "prover.h"
#include "proof.h"
#include "emp_prover.h"
//#include "common.h"
#include "prover_sys.h"
#include "../utils/timer.h"
#include "../../crypto/params.h"
#include "circuit.h"

using namespace std;
using namespace emp;

void GenViewsCtCircuit(block *mShares, int m_len, block *hashInShares, int in_len, block *hashOutShares, block *ctShares, block *keyShares, block *keyCommShares, block *keyRShares, __m128i iv, vector<CircuitView *> &views, block *out, uint8_t seeds[3][32][16], int numRands, uint32_t *idx) {
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


    thread_local ZKBooCircExecProver<AbandonIO> *ex = new ZKBooCircExecProver<AbandonIO>(seeds, w, wLen, numRands, idx);
    if (CircuitExecution::circ_exec != NULL) printf("****** NOT NULL *******\n");
    else printf("*** IS NULL ***\n");
    CircuitExecution::circ_exec = ex;
    cout << "starting for " << this_thread::get_id() << endl;
    check_ciphertext_circuit(ex, hashOutShares, mShares, m_len, hashInShares, in_len, ctShares, iv, keyShares, keyCommShares, keyRShares, out);
    cout << "finished for " << this_thread::get_id() << endl;
    for (int i = 0; i < 2; i++) {
        views.push_back(ex->view[i]);
    }
    delete ex;
}

void CommitViews(vector<CircuitView *> &views, CircuitComm comms[3][32]) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 32; j++) {
            views[i]->Commit(comms[i][j], j);
        }
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
        uint32_t setval = GetBit((uint32_t)input[i/8], i%8) == 0 ? 0 : 0xffffffff;
        RAND_bytes((uint8_t *)&indivShares[0][i], sizeof(uint32_t));
        RAND_bytes((uint8_t *)&indivShares[1][i], sizeof(uint32_t));
        indivShares[2][i] = indivShares[0][i] ^ indivShares[1][i] ^ setval;
        for (int j = 0; j < 3; j++) {
            //SetWireNum(&indivShares[j][i], i + offset);
            memcpy(((uint8_t *)&inputShares[i]) + j * sizeof(uint32_t), (uint8_t *)&indivShares[j][i], sizeof(uint32_t));
            dst[j][i + offset] = indivShares[j][i];
        }
    }
}

void ProveCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, Proof *proof) {
    vector<CircuitView *>views;
    RandomOracle oracle; 

    proof->wLen = m_len + 256 + m_len + 128 + 128 + 256 + in_len;
    uint32_t *w_tmp[3];
    for (int i = 0; i < 3; i++) {
        w_tmp[i] = (uint32_t *)malloc(proof->wLen * sizeof(uint32_t));
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

    uint8_t seeds[3][32][16];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 32; j++) {
            RAND_bytes(seeds[i][j], 16);
        }
    }

    for (int i = 0; i < 32; i++) { 
        proof->idx[i] = oracle.GetRand(proof->comms[0]) % 3;
    }
 
    //INIT_TIMER;
    //START_TIMER;
    GenViewsCtCircuit(mShares, m_len, hashInShares, in_len, hashOutShares, ctShares, keyShares, keyCommShares, keyRShares, iv, views, out, seeds, numRands, proof->idx);
    //STOP_TIMER("Gen views");
    CommitViews(views, proof->comms);
   
    proof->views[0] = views[0];
    proof->views[1] = views[1];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < proof->wLen; j++) {
            uint32_t val;
            for (int k = 0; k < 32; k++) {
                SetBit(&val, k, GetBit(w_tmp[(proof->idx[k] + i) % 3][j], k));
            }
            proof->w[i][j] = val;
        }
    }
    //proof->w[0] = w_tmp[proof->idx];
    //proof->w[1] = w_tmp[(proof->idx + 1) % 3];
    
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

    // TODO run randomness tape on verifier
    for (int i = 0; i < 2; i++) {
        uint8_t seeds_tmp[32][16];
        for (int j = 0; j < 32; j++) {
            memcpy(seeds_tmp[j], seeds[(proof->idx[j] + i) % 3][j], 16);
        }
        proof->rands[i] = new RandomSource(seeds_tmp, numRands);
    }
    //proof->rands[0] = new RandomSource(seeds[proof->idx], numRands);
    //proof->rands[1] = new RandomSource(seeds[(proof->idx+1)%3], numRands);

    proof->outLen = 1;
    bool b;
    for (int i = 0; i < 3; i++) {
        proof->outShares[i] = (uint32_t *)malloc(sizeof(uint32_t));
        memcpy(((uint8_t *)&proof->outShares[i][0]), ((uint8_t *)&out[0]) + i * sizeof(uint32_t), sizeof(uint32_t));
        printf("copying in %d\n", proof->outShares[i][0]);
    }
    uint32_t shares[3];
    for (int j = 0; j < 3; j++) {
        memcpy((uint8_t *)&shares[j], ((uint8_t *)&out[0]) + (sizeof(uint32_t) * j), sizeof(uint32_t));
    }
    b = (shares[0] + shares[1] + shares[2]) % 2;
    proof->out = (uint8_t *)malloc(1);
    proof->out[0] = b;

}

