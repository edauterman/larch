#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

class ShortHint {
    public:
        ShortHint(BIGNUM *xcoord, BIGNUM *auth_xcoord);

        BIGNUM *xcoord;
        BIGNUM *auth_xcoord;
};

class Hint {
    public:
        Hint();
        //Hint(BIGNUM *xcoord_in, BIGNUM *auth_xcoord_in, BIGNUM *r_in, BIGNUM *auth_r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in, BIGNUM *alpha_in);
        Hint(BIGNUM *xcoord_in, BIGNUM *auth_xcoord_in, BIGNUM *auth_r_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in);

        BIGNUM *xcoord;
        BIGNUM *auth_xcoord;
        //BIGNUM *r;
        BIGNUM *auth_r;
        //BIGNUM *a;
        //BIGNUM *b;
        BIGNUM *c;
        BIGNUM *f;
        BIGNUM *g;
        BIGNUM *h;
        //BIGNUM *alpha;
};

#endif
