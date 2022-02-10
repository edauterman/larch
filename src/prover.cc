#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include <openssl/rand.h>

#include "prover.h"

using namespace std;

uint8_t RandomSource::GetRand(int gate, int wireIdx) {
    return 1;
}

uint8_t RandomOracle::GetRand(CircuitComm *in) {
    return 1;
}

void Prover::AddConst(WireVal &in, uint8_t alpha, WireVal &out) {
    out.Copy(in);
    out.shares[0] += alpha % 2;
}

void Prover::MultConst(WireVal &in, uint8_t alpha, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = alpha * in.shares[i];
        out.shares[i] %= 2;
    }
}

void Prover::AddShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = in0.shares[i] + in1.shares[i];
        out.shares[i] %= 2;
    }
}

void Prover::SubShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = in0.shares[i] - in1.shares[i];
        out.shares[i] %= 2;
    }
}

void Prover::MultShares(WireVal &in0, WireVal &in1, WireVal &out) {
    for (int i = 0; i < WIRES; i++) {
        out.shares[i] = (in0.shares[i] * in1.shares[i]) + 
                (in0.shares[(i + 1) % WIRES] * in1.shares[i]) + 
                (in0.shares[i] * in1.shares[(i + 1) % WIRES]) +
                rands[i].GetRand(currGate, i) - rands[(i + 1) % WIRES].GetRand(currGate, (i + 1) % WIRES);
        out.shares[i] %= 2;
    }
}

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

void Prover::CommitViews(CircuitViews &views, CircuitComm *comms) {
    // Commit by hashing views
    for (int i = 0; i < 3; i++) {
        CircuitView v = views.GetView(i);
        v.Commit(comms[i]);
    }
}

void Prover::Prove(CircuitSpec &spec, WireVal w[], Proof &proof) {
    CircuitViews views;
    WireVal out[spec.m];
    GenViews(spec, w, views, out);
    cout << "Generated views" << endl;
    CommitViews(views, proof.comms);
    cout << "Committed to views" << endl;
    
    proof.idx = oracle.GetRand(proof.comms);
    proof.views[0] = views.GetView(proof.idx);
    proof.views[1] = views.GetView((proof.idx + 1) % WIRES);
    proof.rands[0] = rands[proof.idx];
    proof.rands[1] = rands[(proof.idx + 1) % WIRES];

    proof.w[0] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    proof.w[1] = (uint8_t *)malloc(spec.m * sizeof(uint8_t));
    for (int i = 0; i < spec.m; i++) {
        proof.w[0][i] = w[i].shares[proof.idx];
        proof.w[1][i] = w[i].shares[(proof.idx + 1) % WIRES];
    }

}

