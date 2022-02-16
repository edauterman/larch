#ifndef _PROVER_SYS_H_
#define _PROVER_SYS_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <vector>

#include "view.h"
#include "emp_prover.h"

#define WIRES 3

using namespace std;

void GenViews(string circuitFile, uint64_t *w, int wLen, vector<CircuitView> &views, uint64_t *out, int outLen);
void CommitViews(vector<CircuitView> &views, CircuitComm *comms);
void Prove(string circuitFile, uint64_t *w, int wLen, Proof &proof);

#endif
