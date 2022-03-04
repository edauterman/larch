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

inline void GenViews(string circuitFile, block *w, int wLen, vector<CircuitView *> &views, block *out, int outLen, int numRands);
void CommitViews(vector<CircuitView *> &views, CircuitComm *comms);
void Prove(string circuitFile, uint8_t *w, int in_len, int out_len, int numRands, Proof &proof);

#endif
