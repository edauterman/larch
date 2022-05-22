#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "sigs.h"

ShortHint::ShortHint(BIGNUM *xcoord_in) : xcoord(xcoord_in) {}

Hint::Hint() {}

Hint::Hint(BIGNUM *xcoord_in, BIGNUM *r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in) : xcoord(xcoord_in), r(r_in), a(a_in), b(b_in), c(c_in) {}

