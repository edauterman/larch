#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <vector>

#include "params.h"

class ShortHint {
    public:
        ShortHint(BIGNUM *xcoord);

        BIGNUM *xcoord;
};

class Hint {
    public:
        Hint();
        Hint(BIGNUM *xcoord_in, BIGNUM *auth_r_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in);

        BIGNUM *xcoord;
        BIGNUM *auth_r;
        BIGNUM *c;
        BIGNUM *f;
        BIGNUM *g;
        BIGNUM *h;
};

void GetPreprocessValue(uint64_t ctr, BIGNUM *ret, uint8_t *seed_in, Params params);
void GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret, Params params);

#endif
