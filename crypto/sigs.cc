#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>

#include "sigs.h"
#include "params.h"


ShortHint::ShortHint(EC_POINT *R_in) : R(R_in) {}

Hint::Hint() {}

Hint::Hint(EC_POINT *R_in, BIGNUM *r_in, BIGNUM *a_in, BIGNUM *b_in, BIGNUM *c_in) : R(R_in), r(r_in), a(a_in), b(b_in), c(c_in) {}

void RerandomizePresig(Params params, BIGNUM *r, EC_POINT *R, BIGNUM *m, BIGNUM *z, BIGNUM *x_coord) {
  BN_CTX *ctx;
  EC_POINT *Z = EC_POINT_new(Params_group(params));;
  BIGNUM *auth_val = BN_new();
  BIGNUM *auth_hash = BN_new();
  BIGNUM *y_coord = BN_new();
  BIGNUM *k = BN_new();
  BIGNUM *k_inv = BN_new();
  uint8_t hash_in[64];
  uint8_t hash_out[32];
  ctx = BN_CTX_new();

 /* // k = H(m,r)
  BN_bn2bin(m, hash_in);
  BN_bn2bin(r, hash_in + 32);
  hash_to_bytes(hash_out, 32, hash_in, 64); 
  BN_bin2bn(hash_out, 32, k);
  
  // z = k . r
  BN_mod_mul(z, k, r, Params_order(params), ctx);

  // Z = R^{k^{-1}}
  k_inv = BN_mod_inverse(NULL, k, Params_order(params), ctx);
  Params_exp_base(params, Z, R, k_inv);
  EC_POINT_get_affine_coordinates_GFp(Params_group(params), Z, x_coord, y_coord, NULL);
*/
  EC_POINT_get_affine_coordinates_GFp(Params_group(params), R, x_coord, y_coord, NULL);
  BN_copy(z, r);
  fprintf(stderr, "xcoord = %s\n", BN_bn2hex(x_coord));
  fprintf(stderr, "r = %s\n", BN_bn2hex(r));
  fprintf(stderr, "z = %s\n", BN_bn2hex(z));
}

