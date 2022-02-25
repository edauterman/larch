#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "view.h"
#include "prover.h"
#include "prover_sys.h"
#include "verifier.h"

using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int main() {
    cout << "Hello world" << endl;

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
    string circuitFile = circuit_file_location+"/bristol_format/sha-256.txt";
    cout << circuitFile << endl;
    // TODO: should actually be 512/8
    uint8_t *w = (uint8_t *)malloc(512/8);
    int wLen = 0;
    Prove(circuitFile, w, wLen, pi);
    cout << "Finished proving" << endl; 
    bool check = Verify(circuitFile, pi);
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }
    free(w);
    printf("at end\n");
}
