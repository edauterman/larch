#ifndef _CIRCUIT_H_
#define _CIRCUIT_H_

#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>

using namespace emp;

void hash_in_circuit(block output[], block input[], int len);

#endif
