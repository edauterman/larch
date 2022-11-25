#ifndef _DDH_PROOF_H_
#define _DDH_PROOF_H_

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"

class DDHProof {
    public:
        DDHProof(int n);
        BIGNUM **c;
        BIGNUM **r;
        int n;
};

DDHProof *DDHProve(int n, int idx, BIGNUM *x, EC_POINT **g, EC_POINT **y, Params params);
bool DDHVerify(DDHProof *proof, EC_POINT **g, EC_POINT **y, Params params);

#endif
