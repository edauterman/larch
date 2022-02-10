#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#include "verifier.h"
#include "prover.h"
#include "common.h"
#include "view.h"

using namespace std;

// QUESTION: should we just be checking out0???? or is it checking that both inputs used correctly????

bool Verifier::CheckAddConst(int wireIdx, uint8_t in0, uint8_t in1, uint8_t alpha, uint8_t out) {
    if (wireIdx == 0 && ((out != (in0 + alpha) % 2))) {
        return false;
    } else if (wireIdx == 1 && (out != in0)) {
        return false;
    } else if (wireIdx == 2 && (out != in0)) {
        return false;
    }
    return true;
}

bool Verifier::CheckMultConst(uint8_t in0, uint8_t in1, uint8_t alpha, uint8_t out) {
    return ((in0 * alpha) % 2 == out);
}

bool Verifier::CheckAddShares(uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out) {
    return ((a0 + b0) % 2 == out);
}

bool Verifier::CheckSubShares(uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out) {
    return ((a0 - b0) % 2 == out);
}

bool Verifier::CheckMultShares(int currGate, int wireIdx, RandomSource rand0, RandomSource rand1, uint8_t a0, uint8_t a1, uint8_t b0, uint8_t b1, uint8_t out) {
    uint8_t out_check = ((a0 * b0) + (a1 * b1) + (a0 * b1) + rand0.GetRand(currGate, wireIdx) - rand1.GetRand(currGate, (wireIdx + 1) % WIRES)) % 2;
    printf("out = %d, out-check = %d\n", out, out_check);
    return out_check == out;
}

bool Verifier::Verify(CircuitSpec &spec, Proof &proof) {
    CircuitComm c0, c1;
    proof.views[0].Commit(c0);
    proof.views[1].Commit(c1);
    if (memcmp(c0.digest, proof.comms[proof.idx].digest, SHA256_DIGEST_LENGTH) != 0) {
        return false;
    }

    if (memcmp(c1.digest, proof.comms[(proof.idx + 1) % WIRES].digest, SHA256_DIGEST_LENGTH) != 0) {
        return false;
    }

    cout << "passed commit checks" << endl;

    // Need to check that views chosen randomly correctly?

    int idx = 0;
    uint8_t A[2][spec.m];
    uint8_t B[2][spec.m];
    uint8_t C[2][spec.m];
    for (int i = 0; i < spec.m; i++) {
        A[0][i] = 0;
        A[1][i] = 0;
        B[0][i] = 0;
        B[1][i] = 0;
        C[0][i] = 0;
        C[1][i] = 0;
        for (int j = 0; j < spec.n; j++) {
            cout << "i = " << i << ", j = " << j << endl;
            if (!CheckMultConst(proof.w[0][j], proof.w[1][j], spec.A[i][j], proof.views[0].wireShares[idx])) {
                return false;
            }
            idx++;
            if (!CheckAddShares(proof.views[0].wireShares[idx - 1], proof.views[1].wireShares[idx - 1], A[0][i], A[1][i], proof.views[0].wireShares[idx])) {
                return false;
            }
            A[0][i] = proof.views[0].wireShares[idx];
            A[1][i] = proof.views[1].wireShares[idx];
            idx++;
            if (!CheckMultConst(proof.w[0][j], proof.w[1][j], spec.B[i][j], proof.views[0].wireShares[idx])) {
                return false;
            }
            idx++;
            if (!CheckAddShares(proof.views[0].wireShares[idx - 1], proof.views[1].wireShares[idx - 1], B[0][i], B[1][i], proof.views[0].wireShares[idx])) {
                return false;
            }
            B[0][i] = proof.views[0].wireShares[idx];
            B[1][i] = proof.views[1].wireShares[idx];
            idx++;
            if (!CheckMultConst(proof.w[0][j], proof.w[1][j], spec.C[i][j], proof.views[0].wireShares[idx])) {
                return false;
            }
            idx++;
            if (!CheckAddShares(proof.views[0].wireShares[idx - 1], proof.views[1].wireShares[idx - 1], C[0][i], C[1][i], proof.views[0].wireShares[idx])) {
                return false;
            }
            C[0][i] = proof.views[0].wireShares[idx];
            C[1][i] = proof.views[1].wireShares[idx];
            idx++;
        }
        if (!CheckMultShares(idx, proof.idx, proof.rands[0], proof.rands[1], A[0][i], A[1][i], B[0][i], B[1][i], proof.views[0].wireShares[idx])) {
            return false;
        }
        cout << "did mult shares" << endl;
        idx++;
        if (!CheckSubShares(proof.views[0].wireShares[idx - 1], proof.views[1].wireShares[idx - 1], C[0][i], C[1][i], proof.views[0].wireShares[idx])) {
            return false;
        }
        cout << "did sub shares" << endl;
        idx++;
    }
    // TODO check output lines up
    
    return true;
    
}
