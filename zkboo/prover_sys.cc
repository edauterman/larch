#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include <vector>

#include <openssl/rand.h>

#include "prover.h"
#include "emp_prover.h"
#include "common.h"
#include "prover_sys.h"

using namespace std;
using namespace emp;

//template<typename IO>
void GenViews(string circuitFile, uint64_t *w, int wLen, vector<CircuitView> &views, uint64_t *out, int outLen) {
    uint64_t wShares[WIRES];
    uint64_t outShares[WIRES];

    for (int i = 0; i < WIRES; i++) {
        // TODO: need to pass in prover randomness???
        // TODO: witnesses not correct here
        AbandonIO *aio = new AbandonIO();
        FILE *f = fopen(circuitFile.c_str(), "r");
        BristolFormat cf(f);
        CircuitExecution::circ_exec = new ZKBooCircExecProver<AbandonIO>(aio, i);
        //ZKBooCircExecProver<AbandonIO> *ex = new ZKBooCircExecProver<AbandonIO>(aio, i);
        //CircuitExecution::circ_exec = ex;
        block in0 = makeBlock(0, wShares[i]);
        block in1 = makeBlock(0, wShares[(i + 1) % WIRES]);
        block out = makeBlock(0, 0);
        cf.compute(&in0, &in1, &out);
        printf("did compute\n");
        outShares[i] = out[0];
        // TODO need to get view
        //views.push_back(exec->view);
        fclose(f);
    }
}

void CommitViews(vector<CircuitView> &views, CircuitComm *comms) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        views[i].Commit(comms[i]);
    }
}

void Prove(string circuitFile, uint64_t *w, int wLen, Proof &proof) {
    vector<CircuitView> views;
    uint64_t out[8];
    //currGate = 0;
    RandomOracle oracle;
    GenViews(circuitFile, w, wLen, views, out, 8);
    cout << "Generated views" << endl;
    CommitViews(views, proof.comms);
    cout << "Committed to views" << endl;
    
    proof.idx = oracle.GetRand(proof.comms) % WIRES;
    proof.views[0] = views[proof.idx];
    proof.views[1] = views[(proof.idx + 1) % WIRES];
    // TODO: need some way to get random tapes into proof
    //proof.rands[0] = rands[proof.idx];
    //proof.rands[1] = rands[(proof.idx + 1) % WIRES];
/*
    proof.w[0] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    proof.w[1] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    proof.outShares[0] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    proof.outShares[1] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    proof.out = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    for (int i = 0; i < spec.m; i++) {
        proof.w[0][i] = w[i].shares[proof.idx];
        proof.w[1][i] = w[i].shares[(proof.idx + 1) % WIRES];
        proof.outShares[0][i] = out[i].shares[proof.idx];
        proof.outShares[1][i] = out[i].shares[(proof.idx + 1) % WIRES];
        proof.out[i] = (out[i].shares[0] + out[i].shares[1] + out[i].shares[2]) % 2;
        printf("output[%d] = %d\n", i, proof.out[i]);
    }
*/
}

