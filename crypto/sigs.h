#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "params.h"

class ShortHint {
    public:
        ShortHint(EC_POINT *R);

        EC_POINT *R;
};

class Hint {
    public:
        Hint();
        Hint(EC_POINT *R_in, BIGNUM *r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in);

        EC_POINT *R;
        BIGNUM *r;
        BIGNUM *a;
        BIGNUM *b;
        BIGNUM *c;
};

void RerandomizePresig(Params params, BIGNUM *r, EC_POINT *R, BIGNUM *m, BIGNUM *z, BIGNUM *x_coord);

#endif
