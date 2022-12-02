#ifndef _DDH_PROOF_H_
#define _DDH_PROOF_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "params.h"

class DDHProof {
    public:
        BIGNUM *c;
        BIGNUM *v;
        DDHProof(BIGNUM *c_in, BIGNUM *v_in);
};

DDHProof *Prove(Params params, EC_POINT *base1, EC_POINT *base2, BIGNUM *x);
bool Verify(Params params, DDHProof *proof, EC_POINT *base1, EC_POINT *base2, EC_POINT *S1, EC_POINT *S2);

#endif
