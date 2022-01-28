#include <stdlib.h>
#include <stdio.h>

#include <openssl/rand.h>

#include "prover.h"

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
    WireVal A1[spec.m];
    WireVal B1[spec.m];
    WireVal C1[spec.m];
    for (int i = 0; i < spec.m; i++) {
        for (int j = 0; j < spec.n; j++) {
            WireVal tmp;
            MultConst(w[j], spec.A[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, A1[i], tmp);
            views.wires.push_back(tmp);
            MultConst(w[j], spec.B[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, B1[i], tmp);
            views.wires.push_back(tmp);
            MultConst(w[j], spec.C[i][j], tmp);
            views.wires.push_back(tmp);
            AddShares(tmp, C1[i], tmp);
            views.wires.push_back(tmp);
        }
        // A.w * B.w - C.w ?= 0
        MultShares(A1[i], B1[i], out[i]);
        views.wires.push_back(out[i]);
        SubShares(out[i], C1[i], out[i]);
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
    CommitViews(views, proof.comms);
    
    int idx = oracle.GetRand(proof.comms);
    proof.views[0] = views.GetView(idx);
    proof.views[1] = views.GetView((idx + 1) % WIRES);
    proof.rands[0] = rands[idx];
    proof.rands[1] = rands[(idx + 1) % WIRES];
}

