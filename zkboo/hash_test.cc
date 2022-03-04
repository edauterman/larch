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
#include "colors.h"
#include "circuit.h"

using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

void test_hash(string testName, uint8_t *w) { 
    Proof pi;
    //string circuitFile = circuit_file_location+"/bristol_format/sha-256.txt";
    // TODO: should actually be 512/8
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0xff, wLen / 8);
    uint8_t output[SHA256_DIGEST_LENGTH];
    Prove(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    bool check = Verify(hash_in_circuit, pi);
    if (check) {
        cout << GREEN << testName << ": Proof VERIFIED" << RESET << endl;
    } else {
        cout << RED << testName << ": Proof FAILED to verify" << RESET << endl;
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

    bool output_correct = true;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (output[i] != buf[i]) {
            output_correct = false;
        }
    }
    if (output_correct) {
        cout << GREEN << testName << ": Output CORRECT" << RESET << endl;
    } else {
        cout << RED << testName << ": Output INCORRECT" << RESET << endl;
    }

}

int main() {
    uint8_t *input = (uint8_t *)malloc(512/8);
    memset(input, 0xff, 512/8);
    test_hash("0xff hash correct", input);
    memset(input, 0, 512/8);
    test_hash("0 hash correct", input);
    free(input);
}
