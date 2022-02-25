#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include <vector>
#include <string>

#include <openssl/rand.h>

#include "prover.h"
#include "emp_prover.h"
#include "common.h"
#include "prover_sys.h"

using namespace std;
using namespace emp;

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)(x & (1 << bit));
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    *x = *x || (val << bit);
}

//template<typename IO>
void GenViews(string circuitFile, block *w, int wLen, vector<CircuitView *> &views, block *c, int outLen, uint8_t *seeds[]) {
    uint64_t wShares[WIRES];
    uint64_t outShares[WIRES];
 	block* b = NULL;
 	//block* b = new block[0];
    //block* c = new block[256];
 

        // TODO: need to pass in prover randomness???
        // TODO: witnesses not correct here
        //AbandonIO *aio = new AbandonIO();
        FILE *f = fopen(circuitFile.c_str(), "r");
        BristolFormat cf(f);
        printf("n1=%d, n2=%d, n3=%d\n", cf.n1, cf.n2, cf.n3);
        //CircuitExecution::circ_exec = new ZKBooCircExecProver<AbandonIO>(aio, i);
        ZKBooCircExecProver<AbandonIO> *ex = new ZKBooCircExecProver<AbandonIO>(seeds);
        CircuitExecution::circ_exec = ex;
        //block* a = new block[128];
    	//block* b = new block[128];
	    //block* c = new block[128];
        //block in0 = zero_block;
        //block in0 = makeBlock(0, wShares[i]);
        //block in1 = zero_block;
        //block in1 = makeBlock(0, wShares[(i + 1) % WIRES]);
        //block out = zero_block;
        printf("about to compute\n");
        cf.compute(c, w, b);
        // TODO need to deal with output
        //outShares[i] = out[0];
        // TODO need to get view
        for (int i = 0; i < 3; i++) {
            views.push_back(ex->view[i]);
        }
        // TODO cleanup
        delete ex;
        //fclose(f);
    
    // ISSUE DELETING THESE
    //delete a;
    //delete b;
    //delete c;
    printf("done with the 3 gen views\n");
}

void CommitViews(vector<CircuitView *> &views, CircuitComm *comms) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        views[i]->Commit(comms[i]);
    }
}

// each block just contains one bit
void Prove(string circuitFile, uint8_t *w, int wLen, Proof &proof) {
    vector<CircuitView *> views;
    int out_len = 256;
    block *out = new block[out_len];
    int len = 512;
    block *wShares = (block *)malloc(len * sizeof(block));
    uint32_t *indivShares[3];
    for (int i = 0; i < 3; i++) {
        indivShares[i] = (uint32_t *)malloc(len * sizeof(uint32_t));
    }
    printf("going to do shares of w\n");
    for (int i = 0; i < len; i++) {
        // individual shares of bits
        RAND_bytes((uint8_t *)&indivShares[0][i], sizeof(uint32_t));
        RAND_bytes((uint8_t *)&indivShares[1][i], sizeof(uint32_t));
        indivShares[0][i] = indivShares[0][i] % 2;
        indivShares[1][i] = indivShares[1][i] % 2;
        printf("before - %d, %d\n", i/(8 * sizeof(uint32_t)), i % (8 * sizeof(uint32_t)));
        indivShares[2][i] = indivShares[0][i] ^ indivShares[1][i] ^ GetBit(w[i/(8 * sizeof(uint32_t))], i % (8 * sizeof(uint32_t)));
        printf("did indiv shares %d/%d\n", i, len);
        for (int j = 0; j < 3; j++) {
            memcpy(((uint8_t *)&wShares[i]), (uint8_t *)&indivShares[0][i], sizeof(uint32_t));
            memcpy(((uint8_t *)&wShares[i]) + sizeof(uint32_t), (uint8_t *)&indivShares[1][i], sizeof(uint32_t));
            memcpy(((uint8_t *)&wShares[i]) + 2 * sizeof(uint32_t), (uint8_t *)&indivShares[2][i], sizeof(uint32_t));
        } 
    }
    printf("finished shares of w\n");
    //currGate = 0;
    RandomOracle oracle;
    uint8_t *seeds[3];
    for (int i = 0; i < 3; i++) {
        seeds[i] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
        RAND_bytes(seeds[i], SHA256_DIGEST_LENGTH);
    }
    printf("about to gen views\n");
    GenViews(circuitFile, wShares, len, views, out, 8, seeds);
    cout << "Generated views" << endl;
    CommitViews(views, proof.comms);
    cout << "Committed to views" << endl;
    
    proof.idx = oracle.GetRand(proof.comms) % WIRES;
    proof.views[0] = views[proof.idx];
    proof.views[1] = views[(proof.idx + 1) % WIRES];
    memcpy(proof.rands[0].seed, seeds[proof.idx], SHA256_DIGEST_LENGTH);
    memcpy(proof.rands[1].seed, seeds[(proof.idx + 1) % 3], SHA256_DIGEST_LENGTH);

    proof.w[0] = (uint8_t *)malloc(len * sizeof(uint32_t));
    proof.w[1] = (uint8_t *)malloc(len * sizeof(uint32_t));
    memcpy(proof.w[0], indivShares[proof.idx], len * sizeof(uint32_t));
    memcpy(proof.w[1], indivShares[(proof.idx + 1) % 3], len * sizeof(uint32_t));
    proof.outShares[0] = (uint32_t *)malloc(out_len * sizeof(uint32_t));
    proof.outShares[1] = (uint32_t *)malloc(out_len * sizeof(uint32_t));
    for (int i = 0; i < out_len; i++) {
        memcpy(((uint8_t *)&proof.outShares[0][i]), ((uint8_t *)&out[i]) + proof.idx * sizeof(uint32_t), sizeof(uint32_t));
        //memcpy(((uint8_t *)&proof.outShares[0]) + (i * sizeof(uint32_t)), ((uint8_t *)&out[i]) + proof.idx * sizeof(uint32_t), sizeof(uint32_t));
        memcpy(((uint8_t *)&proof.outShares[1][i]), ((uint8_t *)&out[i]) + ((proof.idx + 1) % 3) * sizeof(uint32_t), sizeof(uint32_t));
        //memcpy(((uint8_t *)&proof.outShares[1]) + (i * sizeof(uint32_t)), ((uint8_t *)&out[i]) + ((proof.idx + 1) % 3) * sizeof(uint32_t), sizeof(uint32_t));
    }
}

