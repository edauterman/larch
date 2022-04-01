#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "sigs.h"

ShortHint::ShortHint(EC_POINT *R_in) : R(R_in) {}

Hint::Hint() {}

Hint::Hint(BIGNUM *r_in, EC_POINT *R_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in) : r(r_in), R(R_in), a(a_in), b(b_in), c(c_in) {}

