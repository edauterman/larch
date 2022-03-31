#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>


class Hint {
    public:
        Hint(BIGNUM *r_in, EC_POINT *R_in);

        EC_POINT *R;
        BIGNUM *r;
};

class Triple {
    public:
        Triple(BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in);

        BIGNUM *a;
        BIGNUM *b;
        BIGNUM *c;
};

#endif
