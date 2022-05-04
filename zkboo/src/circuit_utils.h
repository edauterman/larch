#ifndef _CIRCUIT_UTILS_H_
#define _CIRCUIT_UTILS_H_

#include <emp-tool/emp-tool.h>

using namespace emp;

void sha256(block *input, block *output, int input_len, CircuitExecution *ex);
void sha256_test();
void hmac(block *key, int key_len, block *data, int data_len, block *output);
void hmac_test();
void print_hash(block *output);
void print_many_bytes(block *output, int num_bytes);

#endif
