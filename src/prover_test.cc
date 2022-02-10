#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "view.h"
#include "prover.h"
#include "verifier.h"

using namespace std;

int main() {
    cout << "Hello world" << endl;

    CircuitSpec spec;
    spec.m = 4;
    spec.n = 4;
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
            spec.C[i][j] = 0;
        }
    }
    
    WireVal *w;
    w = (WireVal *)malloc(spec.n * sizeof(WireVal));
    for (int i = 0; i < spec.n; i++) {
        w[i].shares[0] = 0;
        w[i].shares[1] = 0;
        w[i].shares[2] = 0;
    }

    cout << "Going to prove" << endl;

    Prover p;
    Proof pi;
    cout << "witness before calling prove: " << w[0].shares[0] << endl;
    p.Prove(spec, w, pi);
    cout << "Finished proving" << endl; 
    Verifier v;
    bool check = v.Verify(spec, pi);
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }
}
