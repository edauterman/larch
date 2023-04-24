#ifndef _OR_GROTH_H_
#define _OR_GROTH_H_

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"

class OrProof {
    public:
        OrProof();
        OrProof(EC_POINT **c_l, EC_POINT **c_a, EC_POINT **c_b, EC_POINT**c_d, BIGNUM **f, BIGNUM **z_a, BIGNUM **z_b, BIGNUM *z_d, int len, int log_len);
        void Serialize(Params params, uint8_t **buf, int *len);
        void Deserialize(Params params, const uint8_t *buf);
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

void OrVerify(Params params, EC_POINT *h, OrProof *proof, EC_POINT **cms, int len, int log_len, bool *res);
void OrProve(Params params, EC_POINT *h, EC_POINT **cms, int idx, int len, int log_len, BIGNUM *open, OrProof **proof);

#endif
