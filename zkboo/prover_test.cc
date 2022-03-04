#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <emp-tool/emp-tool.h>

#include "view.h"
#include "prover.h"
#include "prover_sys.h"
#include "verifier.h"
#include "timer.h"

using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int main() {

    /*WireVal *w;
    w = (WireVal *)malloc(spec.n * sizeof(WireVal));
    for (int i = 0; i < spec.n; i++) {
        w[i].shares[0] = 1;
        w[i].shares[1] = 1;
        w[i].shares[2] = 1;
    }*/

    Proof pi;
    //cout << "witness before calling prove: " << w[0].shares[0] << endl;
    // TODO use real params
    string circuitFile = circuit_file_location+"/bristol_format/sha-256.txt";
    // TODO: should actually be 512/8
    uint8_t *w = (uint8_t *)malloc(512/8);
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0, wLen / 8);
    INIT_TIMER;
    START_TIMER;
    Prove(circuitFile, w, wLen, numRands, pi);
    STOP_TIMER("Prover time");
    cout << "Finished proving" << endl; 
    START_TIMER;
    bool check = Verify(circuitFile, pi);
    STOP_TIMER("Verifier time");
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }

    uint8_t buf[SHA256_DIGEST_LENGTH];
    sha3_256(buf, w, 512/8);
/*    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, w, 512/8);
    EVP_DigestFinal(mdctx, buf, NULL);
    printf("CORRECT OUTPUT len %d: ", SHA256_DIGEST_LENGTH);*/
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%x", buf[i]);
    }
    printf("\n");

    free(w);
    printf("at end\n");
}
