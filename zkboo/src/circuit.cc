#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include <openssl/sha.h>
#include "circuit.h"
#include "circuit_utils.h"

using namespace std;
using namespace emp;

void hash_in_circuit(block output[], block input[], int len) {

    SHA3_256_Calculator sha3_256_calc = SHA3_256_Calculator();
    sha3_256_calc.sha3_256(output, (const block *)input, len);
    //sha3_256_calc.sha3_256(output, input, len);

    /*bool bs[256];
    for (int i = 0; i < 256; i++) {
        bs[i] = getLSB(output[i]);
    }
    //ProtocolExecution::prot_exec->reveal(bs, PUBLIC, output, 256);
    from_bool(bs, output_bytes, 256);
    printf("output bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%x", output_bytes[i]);
    }
    printf("\n");*/
    //sha3_256_calc.sha3_256(output, input, len);

}

// TODO: some of this can be out-of-circuit info
void check_ciphertext_circuit(block hash_out[], block m[], int m_len, block hash_in[], int in_len, block ct[], const __m128i iv, block key[], block key_comm[], block key_r[], block res[]) {
    *res = CircuitExecution::circ_exec->public_label(1);

    // H(hash_in) ?= hash_out
    block hash_out_calc[256];
    sha256(hash_in, hash_out_calc, in_len);

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
    block key_and_r[512];
    memcpy((uint8_t *)key_and_r, (uint8_t *)key, 128 * sizeof(block));
    memcpy((uint8_t *)key_and_r + 128 * sizeof(block), (uint8_t *)key_r, 128 * sizeof(block));
    for (int i = 0; i < 256; i++) {
        key_and_r[i + 256] = CircuitExecution::circ_exec->public_label(false);
    }
    sha256(key_and_r, hash_out_calc, 512);

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
    
}
