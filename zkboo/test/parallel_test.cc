#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <emp-tool/emp-tool.h>
//#include "omp.h"

#include "../src/view.h"
#include "../src/prover.h"
#include "../src/prover_sys.h"
#include "../src/verifier.h"
#include "../utils/timer.h"
#include "../src/circuit.h"

using namespace std;
using namespace emp;

#define NUM_ROUNDS 5
#define NUM_REPS 1
//#define NUM_REPS 100

int main() {

    Proof pi[NUM_ROUNDS];
    int numRands = 81543;
    //int numRands = 89984;

    int m_len = 256;
    //int in_len = 512;
    int in_len = 552;
    uint8_t key[128 / 8];
    __m128i key_raw = makeBlock(0,0);
    __m128i iv = makeBlock(0,0);
    __m128i r_raw = makeBlock(0,0);
    uint8_t r[128 / 8];
    uint8_t comm[128 / 8];
    uint8_t *m = (uint8_t *)malloc(m_len / 8);
    uint8_t *ct = (uint8_t *)malloc(m_len / 8);
    uint8_t *hash_in = (uint8_t *)malloc(in_len / 8);
    uint8_t hash_out[256 / 8];
    uint8_t comm_in[256 / 8];
    
    memset(m, 0, m_len/8);
    memset(hash_in, 0xff, in_len/8);
    memset(hash_in, 0, m_len/8);
    memset(key, 0, 128/8);
    //sha3_256(hash_out, hash_in, in_len / 8);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, hash_in, in_len/8);
    EVP_DigestFinal(mdctx, hash_out, NULL);

    memset(r, 0xff, 128/8);
    memcpy((uint8_t *)&r_raw, r, 128 / 8);

    memset(key, 0, 128/8);
    aes_128_ctr(key_raw, iv, m, ct, m_len / 8, 0);

    aes_128_ctr(r_raw, iv, key, comm, 128 / 8, 0);

    //printf("finished setup, starting proving with %d threads\n", omp_get_num_threads());
    INIT_TIMER;
    START_TIMER;
    //#pragma omp parallel for
    thread workers[NUM_ROUNDS];
    for (int reps = 0; reps < NUM_REPS; reps++) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
        //ProveCtCircuit(m, m_len, (uint8_t *)hash_in, in_len, (uint8_t *)hash_out, (uint8_t *)ct, (uint8_t *)key, (uint8_t *)comm, (uint8_t *)r, iv, numRands, &pi[i]);
            workers[i] = thread(ProveCtCircuit, m, m_len, (uint8_t *)hash_in, in_len, (uint8_t *)hash_out, (uint8_t *)ct, (uint8_t *)key, (uint8_t *)comm, (uint8_t *)r, iv, numRands, &pi[i]);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers[i].join();
        }
    }
    STOP_TIMER("Prover time (100)");
    cout << "Finished proving" << endl; 
    START_TIMER;
    bool check[NUM_ROUNDS];
    bool final_check = true;
    thread workers2[NUM_ROUNDS];
    for (int reps = 0; reps < NUM_REPS; reps++) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers2[i] = thread(VerifyCtCircuit, &pi[i], iv, m_len, in_len, hash_out, comm, ct, &check[i]);
        //check = VerifyCtCircuit(pi[0], iv, m_len, in_len, hash_out, comm, ct);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers2[i].join();
            final_check = final_check && check[i];
        }
    }
    STOP_TIMER("Verifier time");
    if (final_check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }

}
