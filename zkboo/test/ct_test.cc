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

    Proof pi;
    int numRands = 103424;
    //int numRands = 89984;

    int m_len = 512;
    uint8_t key[128 / 8];
    __m128i key_raw = makeBlock(0,0);
    __m128i iv = makeBlock(0,0);
    uint8_t r[128 / 8];
    uint8_t comm[256 / 8];
    uint8_t *m = (uint8_t *)malloc(m_len / 8);
    uint8_t *ct = (uint8_t *)malloc(m_len / 8);
    uint8_t hash_out[256 / 8];
    uint8_t comm_in[512 / 8];
    
    memset(m, 0, m_len/8);
    memset(key, 0, 128/8);
    sha3_256(hash_out, m, m_len / 8);
    memset(comm_in, 0, 512 / 8);
    memcpy(comm_in, key, 128 / 8);
    memcpy(comm_in + (128 / 8), r, 128 / 8);
    sha3_256(comm, comm_in, (512) / 8);
    memset(key, 0, 128/8);
    aes_128_ctr(key_raw, iv, m, ct, m_len / 8, 0);

    printf("finished setup, starting proving\n");
    INIT_TIMER;
    START_TIMER;
    ProveCtCircuit(m, m_len, hash_out, ct, key, comm, r, iv, numRands, pi);
    STOP_TIMER("Prover time");
    cout << "Finished proving" << endl; 
    START_TIMER;
    bool check = VerifyCtCircuit(pi, iv);
    STOP_TIMER("Verifier time");
    if (check) {
        cout << "Proof verified" << endl;
    } else {
        cout << "Proof FAILED to verify" << endl;
    }

}
