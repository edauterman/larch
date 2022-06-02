#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "sigs.h"
#include "params.h"


ShortHint::ShortHint(EC_POINT *R_in) : R(R_in) {}

Hint::Hint() {}

Hint::Hint(EC_POINT *R_in, BIGNUM *r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in) : R(R_in), r(r_in), a(a_in), b(b_in), c(c_in) {}

void ProcessPresig(Params params, BIGNUM *r, EC_POINT *R, BIGNUM *z, BIGNUM *x_coord) {
  BIGNUM *y_coord = BN_new();

  EC_POINT_get_affine_coordinates_GFp(Params_group(params), R, x_coord, y_coord, NULL);
  BN_copy(z, r);
}

