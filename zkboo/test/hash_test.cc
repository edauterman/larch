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
#include "../utils/colors.h"
#include "../src/circuit.h"

using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

void test_hash(string testName, uint8_t *w) { 
    Proof pi;
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

void test_bad_commit(string testName, uint8_t *w) { 
    Proof pi;
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0xff, wLen / 8);
    uint8_t output[SHA256_DIGEST_LENGTH];
    Prove(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    // Zero out commit
    memset(pi.comms[pi.idx].digest, 0, SHA256_DIGEST_LENGTH);
    bool check = Verify(hash_in_circuit, pi);
    if (check) {
        cout << RED << testName << ": Proof VERIFIED" << RESET << endl;
    } else {
        cout << GREEN << testName << ": Proof FAILED to verify" << RESET << endl;
    }
}

void test_bad_idx(string testName, uint8_t *w) { 
    Proof pi;
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0xff, wLen / 8);
    uint8_t output[SHA256_DIGEST_LENGTH];
    Prove(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    // Increase index 
    pi.idx = (pi.idx + 1) % 3;
    bool check = Verify(hash_in_circuit, pi);
    if (check) {
        cout << RED << testName << ": Proof VERIFIED" << RESET << endl;
    } else {
        cout << GREEN << testName << ": Proof FAILED to verify" << RESET << endl;
    }
}

void test_bad_rands(string testName, uint8_t *w) { 
    Proof pi;
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0xff, wLen / 8);
    uint8_t output[SHA256_DIGEST_LENGTH];
    Prove(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    // Bad randomness 
    uint8_t seed[16];
    memset(seed, 0, 16);
    pi.rands[0] = new RandomSource(seed, numRands);
    bool check = Verify(hash_in_circuit, pi);
    if (check) {
        cout << RED << testName << ": Proof VERIFIED" << RESET << endl;
    } else {
        cout << GREEN << testName << ": Proof FAILED to verify" << RESET << endl;
    }
}

void test_bad_view(string testName, uint8_t *w) { 
    Proof pi;
    int wLen = 512;
    int numRands = 38400;
    //int numRands = 22272;
    memset(w, 0xff, wLen / 8);
    uint8_t output[SHA256_DIGEST_LENGTH];
    Prove(hash_in_circuit, w, wLen, 256, numRands, pi, output);
    // Flip bit in view 
    uint8_t seed[16];
    memset(seed, 0, 16);
    pi.views[0]->wires[100] = pi.views[0]->wires[100] ^ 1;
    bool check = Verify(hash_in_circuit, pi);
    if (check) {
        cout << RED << testName << ": Proof VERIFIED" << RESET << endl;
    } else {
        cout << GREEN << testName << ": Proof FAILED to verify" << RESET << endl;
    }
}


int main() {
    uint8_t *input = (uint8_t *)malloc(512/8);
    memset(input, 0xff, 512/8);
    test_hash("0xff hash correct", input);
    memset(input, 0, 512/8);
    test_hash("0 hash correct", input);
    test_bad_commit("Bad commit", input);
    test_bad_idx("Bad index", input);
    test_bad_rands("Bad randomness", input);
    test_bad_view("Bad view", input);
    free(input);
}
