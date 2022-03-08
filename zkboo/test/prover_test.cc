#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <emp-tool/emp-tool.h>

#include "../src/view.h"
#include "../src/prover.h"
#include "../src/prover_sys.h"
#include "../src/verifier.h"
#include "../utils/timer.h"
#include "../src/circuit.h"

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
    uint8_t output[SHA256_DIGEST_LENGTH];
    INIT_TIMER;
    START_TIMER;
    ProveHash(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    //Prove(circuitFile, w, wLen, 256, numRands, pi);
    STOP_TIMER("Prover time");
    cout << "Finished proving" << endl; 
    START_TIMER;
    bool check = VerifyHash(hash_in_circuit, pi);
    STOP_TIMER("Verifier time");
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }

    /*
    setup_plain_prot(false, "");
    Integer inp = Integer(512, 0, PUBLIC);

    Integer out = Integer(256, 0, PUBLIC);

    printf("going to set up\n");
    cout << circuitFile << endl;
    BristolFormat cf(circuitFile.c_str());
    printf("about to compute\n");
    cf.compute(out.bits.data(), inp.bits.data(), NULL);
    printf("did compute\n");
    std::cout << out.reveal<string>() << std::endl;
    finalize_plain_prot();*/

    uint8_t buf[SHA256_DIGEST_LENGTH];
    sha3_256(buf, w, 512/8);
    /*EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, w, 512/8);
    EVP_DigestFinal(mdctx, buf, NULL);*/
    printf("CORRECT OUTPUT len %d: ", SHA256_DIGEST_LENGTH);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%x", buf[i]);
    }
    printf("\n");

    bool output_correct = true;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (output[i] != buf[i]) {
            output_correct = false;
        }
    }
    if (output_correct) {
        printf("Output CORRECT\n");
    } else {
        printf("Output INCORRECT\n");
    }

    free(w);
    printf("at end\n");
}
