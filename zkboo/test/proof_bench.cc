#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <vector>
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

#define NUM_ROUNDS 5 
#define NUM_REPS 100

int main(int argc, char **argv) {

    string out_file(argv[1]);
    Proof pi[NUM_ROUNDS];
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
    uint8_t comm_in[256 / 8];
    
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
    thread workers[NUM_ROUNDS];
    uint8_t *proof_buf[NUM_ROUNDS];
    int proof_buf_len[NUM_ROUNDS];
    sem_t proof_semas[NUM_ROUNDS];
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int reps = 0; reps < NUM_REPS; reps++) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers[i] = thread(ProveSerializeCtCircuit, m, m_len, (uint8_t *)hash_in, in_len, (uint8_t *)hash_out, (uint8_t *)ct, (uint8_t *)key, (uint8_t *)comm, (uint8_t *)r, iv, numRands, &proof_buf[i], &proof_buf_len[i], &proof_semas[i]);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers[i].join();
        }
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    cout << "Finished proving" << endl; 
    bool check[NUM_ROUNDS];
    bool final_check = true;
    thread workers2[NUM_ROUNDS];
    for (int reps = 0; reps < NUM_REPS; reps++) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers2[i] = thread(VerifyDeserializeCtCircuit, proof_buf[i], numRands, iv, m_len, in_len, hash_out, comm, ct, &check[i]);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers2[i].join();
            final_check = final_check && check[i];
        }
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    double proveMs = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() / (double)NUM_REPS;
    double verifyMs = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() / (double)NUM_REPS;
    if (final_check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }
    cout << "Prove (ms) " << proveMs << endl;
    cout << "Verify (ms) " << verifyMs << endl;
    ofstream f;
    f.open(out_file);
    f << proveMs << endl;
    f << verifyMs << endl;
}
