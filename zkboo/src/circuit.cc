#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include <openssl/sha.h>
#include "circuit.h"
#include "circuit_utils.h"
#include "../utils/timer.h"

using namespace std;
using namespace emp;

void check_ciphertext_circuit(CircuitExecution *ex, block hash_out[], block m[], int m_len, block hash_in[], int in_len, block ct[], const __m128i iv, block key[], block key_comm[], block key_r[], block res[]) {
    *res = CircuitExecution::circ_exec->public_label(1);

    // H(hash_in) ?= hash_out
    block hash_out_calc[256];
    sha256(hash_in, hash_out_calc, in_len, ex);

    // m in beginning of hash_in
    for (int i = 0; i < m_len; i++) {
        block out = CircuitExecution::circ_exec->xor_gate(m[i], hash_in[i]);
        out = CircuitExecution::circ_exec->not_gate(out);
        *res = CircuitExecution::circ_exec->and_gate(*res, out);
    }

    // Check hash matches
    for (int i = 0; i < 256; i++) {
        block out = CircuitExecution::circ_exec->xor_gate(hash_out[i], hash_out_calc[i]);
        out = CircuitExecution::circ_exec->not_gate(out);
        *res = CircuitExecution::circ_exec->and_gate(*res, out);
    }

    // H(key, key_r) ?= key_comm
    block key_and_r[256];
    memcpy((uint8_t *)key_and_r, (uint8_t *)key, 128 * sizeof(block));
    memcpy((uint8_t *)key_and_r + 128 * sizeof(block), (uint8_t *)key_r, 128 * sizeof(block));
    sha256(key_and_r, hash_out_calc, 256, ex);

    // Check hash matches
    for (int i = 0; i < 256; i++) {
        block out = CircuitExecution::circ_exec->xor_gate(key_comm[i], hash_out_calc[i]);
        out = CircuitExecution::circ_exec->not_gate(out);
        *res = CircuitExecution::circ_exec->and_gate(*res, out);
    }

    // Enc(k, iv, m) ?= ct
    block *ct_calc = new block[m_len];
    AES_128_CTR_Calculator aes128_calc = AES_128_CTR_Calculator();
    aes128_calc.aes_128_ctr(key, iv, m, ct_calc, m_len, 0);

    // Check ciphertext matches
    for (int i = 0; i < m_len; i++) {
        block out = CircuitExecution::circ_exec->xor_gate(ct_calc[i], ct[i]);
        out = CircuitExecution::circ_exec->not_gate(out);
        *res = CircuitExecution::circ_exec->and_gate(*res, out);
    }
    //printf("total: %d\n", ex->num_and());
}
