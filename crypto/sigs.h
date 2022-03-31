#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

class ShortHint {
    public:
        ShortHint(EC_POINT *R_in);

        EC_POINT *R;
};

class Hint {
    public:
        Hint(BIGNUM *r_in, EC_POINT *R_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in);

        EC_POINT *R;
        BIGNUM *r;
        BIGNUM *a;
        BIGNUM *b;
        BIGNUM *c;
};

#endif
