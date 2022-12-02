#ifndef _OR_GROTH_H_
#define _OR_GROTH_H_

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"

class OrProof {
    public:
        OrProof(EC_POINT **c_l, EC_POINT **c_a, EC_POINT **c_b, EC_POINT**c_d, BIGNUM **f, BIGNUM **z_a, BIGNUM **z_b, BIGNUM *z_d, int len, int log_len);
        EC_POINT **c_l;
        EC_POINT **c_a;
        EC_POINT **c_b;
        EC_POINT **c_d;
        BIGNUM **f;
        BIGNUM **z_a;
        BIGNUM **z_b;
        BIGNUM *z_d;
        int len;
        int log_len;
};

bool Verify(Params params, OrProof *proof, EC_POINT **cms, int len, int log_len);
OrProof *Prove(Params params, EC_POINT **cms, int idx, int len, int log_len, BIGNUM *open);

#endif
