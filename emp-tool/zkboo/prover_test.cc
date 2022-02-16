#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "view.h"
#include "prover.h"
#include "prover_sys.h"
#include "verifier.h"

using namespace std;

int main() {
    cout << "Hello world" << endl;

    CircuitSpec spec;
    spec.m = 5;
    spec.n = 5;
    spec.A = (uint8_t **)malloc(spec.m * sizeof(uint8_t *));
    spec.B = (uint8_t **)malloc(spec.m * sizeof(uint8_t *));
    spec.C = (uint8_t **)malloc(spec.m * sizeof(uint8_t *));
    for (int i = 0; i < spec.m; i++) {
        spec.A[i] = (uint8_t *)malloc(spec.n * sizeof(uint8_t));
        spec.B[i] = (uint8_t *)malloc(spec.n * sizeof(uint8_t));
        spec.C[i] = (uint8_t *)malloc(spec.n * sizeof(uint8_t));
        for (int j = 0; j < spec.n; j++) {
            spec.A[i][j] = 0;
            spec.B[i][j] = 0;
            spec.C[i][j] = 1; // should be 0
        }
    }
    
    /*WireVal *w;
    w = (WireVal *)malloc(spec.n * sizeof(WireVal));
    for (int i = 0; i < spec.n; i++) {
        w[i].shares[0] = 1;
        w[i].shares[1] = 1;
        w[i].shares[2] = 1;
    }*/

    cout << "Going to prove" << endl;

    Proof pi;
    //cout << "witness before calling prove: " << w[0].shares[0] << endl;
    // TODO use real params
    string circuitFile;
    uint64_t *w = NULL;
    int wLen = 0;
    Prove(circuitFile, w, wLen, pi);
    cout << "Finished proving" << endl; 
    Verifier v;
    bool check = v.Verify(spec, pi);
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }
}
