#ifndef _PROVER_SYS_H_
#define _PROVER_SYS_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <vector>
#include <iostream>
#include <emp-tool/emp-tool.h>

#include "view.h"
//#include "emp_prover.h"

#define WIRES 3

using namespace std;
using namespace emp;

class AbandonIO: public IOChannel<AbandonIO> { public:
    void send_data_internal(const void * data, int len) {
    }   

    void recv_data_internal(void  * data, int len) {
    }   
};

inline void GenViews(void (*f)(block[], block[], int), block *w, int wLen, vector<CircuitView *> &views, block *out, int outLen, int numRands);
void CommitViews(vector<CircuitView *> &views, CircuitComm *comms);
void ProveSerializeCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, uint8_t **proof_bytes, int *proof_len);
void ProveCtCircuit(uint8_t *m, int m_len, uint8_t *hashIn, int in_len, uint8_t *hashOut, uint8_t *ct, uint8_t *key, uint8_t *keyComm, uint8_t *keyR, __m128i iv, int numRands, Proof *proof);
void ProveHash(void (*f)(block[], block[], int), uint8_t *w, int in_len, int out_len, int numRands, Proof *proof, uint8_t *output);

#endif
