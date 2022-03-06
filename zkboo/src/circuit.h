#ifndef _CIRCUIT_H_
#define _CIRCUIT_H_

#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>

using namespace emp;

void check_ciphertext_circuit(block hash_out[], block m[], int m_len, block ct[], const __m128i iv, block key[], block key_comm[], block key_r[], block res[]);
void hash_in_circuit(block output[], block input[], int len);

#endif
