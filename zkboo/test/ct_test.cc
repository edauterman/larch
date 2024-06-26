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

#define NUM_REPS 10

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int main() {

    Proof pi;
    int numRands = 81543;

    int m_len = 256;
    int in_len = 552;
    uint8_t key[128 / 8];
    __m128i key_raw = makeBlock(0,0);
    __m128i iv = makeBlock(0,0);
    uint8_t r[128 / 8];
    uint8_t comm[256 / 8];
    uint8_t *m = (uint8_t *)malloc(m_len / 8);
    uint8_t *ct = (uint8_t *)malloc(m_len / 8);
    uint8_t *hash_in = (uint8_t *)malloc(in_len / 8);
    uint8_t hash_out[256 / 8];
    uint8_t comm_in[512 / 8];
    
    memset(m, 0, m_len/8);
    memset(hash_in, 0xff, in_len/8);
    memset(hash_in, 0, m_len/8);
    memset(key, 0, 128/8);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, hash_in, in_len/8);
    EVP_DigestFinal(mdctx, hash_out, NULL);

    memset(r, 0xff, 128/8);
    memset(comm_in, 0, 256 / 8);
    memcpy(comm_in, key, 128 / 8);
    memcpy(comm_in + (128 / 8), r, 128 / 8);
    EVP_MD_CTX *mdctx2 = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx2, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx2, comm_in, 256/8);
    EVP_DigestFinal(mdctx2, comm, NULL);

    memset(key, 0, 128/8);
    aes_128_ctr(key_raw, iv, m, ct, m_len / 8, 0);

    INIT_TIMER;
    START_TIMER;
    //for (int i = 0; i < 1; i++) {
    for (int i = 0; i < NUM_REPS; i++) {
        ProveCtCircuit(m, m_len, hash_in, in_len, hash_out, ct, key, comm, r, iv, numRands, &pi);
    }
    STOP_TIMER("Prover time (1)");
    cout << "Finished proving" << endl; 
    START_TIMER;
    bool check;
    for (int i = 0; i < NUM_REPS; i++) {
        VerifyCtCircuit(&pi, iv, m_len, in_len, hash_out, comm, ct, &check);
    }
    STOP_TIMER("Verifier time");
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }

    uint8_t hash_out2[32];
    memset(hash_out2, 0xff, 32);
    VerifyCtCircuit(&pi, iv, m_len, in_len, hash_out2, comm, ct, &check);
    if (!check) {
        cout << "Proof correctly rejected" << endl;
    } else {
        cout << "Proof FAILED to correctly reject" << endl;
    }

    free(m);
    free(ct);
    free(hash_in);
    EVP_MD_CTX_destroy(mdctx);
    EVP_MD_CTX_destroy(mdctx2);
}
