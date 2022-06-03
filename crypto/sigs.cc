#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "sigs.h"

ShortHint::ShortHint(BIGNUM *xcoord_in, BIGNUM *auth_xcoord_in) : xcoord(xcoord_in), auth_xcoord(auth_xcoord_in) {}

Hint::Hint() {}

//Hint::Hint(BIGNUM *xcoord_in, BIGNUM *auth_xcoord_in, BIGNUM *r_in, BIGNUM *auth_r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in, BIGNUM *alpha_in) : xcoord(xcoord_in), auth_xcoord(auth_xcoord_in), r(r_in), auth_r(auth_r_in), a(a_in), b(b_in), c(c_in), f(f_in), g(g_in), h(h_in), alpha(alpha_in) {}
Hint::Hint(BIGNUM *xcoord_in, BIGNUM *auth_xcoord_in, BIGNUM *auth_r_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in) : xcoord(xcoord_in), auth_xcoord(auth_xcoord_in), auth_r(auth_r_in), c(c_in), f(f_in), g(g_in), h(h_in) {}


