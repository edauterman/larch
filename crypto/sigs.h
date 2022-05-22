#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

class ShortHint {
    public:
        ShortHint(BIGNUM *xcoord);

        BIGNUM *xcoord;
};

class Hint {
    public:
        Hint();
        Hint(BIGNUM *xcoord_in, BIGNUM *r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in);

        BIGNUM *xcoord;
        BIGNUM *r;
        BIGNUM *a;
        BIGNUM *b;
        BIGNUM *c;
};

#endif
