#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <vector>

#include "sigs.h"
#include "params.h"

void ECDSASign(uint8_t *message_buf, int message_buf_len, const BIGNUM *sk, uint8_t **sig_out, unsigned int *sig_len, Params params) {
  BIGNUM *out = NULL;
  BIGNUM *r, *r_inv, *x_coord, *y_coord, *val, *hash_bn;
  EC_POINT *R;
  EC_POINT *pk;
  EVP_MD_CTX *mdctx2;
  uint8_t message[SHA256_DIGEST_LENGTH];
  BN_CTX *ctx;
  uint8_t len_byte;
  uint8_t hash_out[32];

  out = BN_new();
  hash_bn = BN_new();
  val = BN_new();
  r = BN_new();
  x_coord = BN_new();
  y_coord = BN_new();
  mdctx2 = EVP_MD_CTX_create();
  ctx = Params_ctx(params);
  R = EC_POINT_new(Params_group(params));
  pk = EC_POINT_new(Params_group(params));

  EVP_DigestInit_ex(mdctx2, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx2, message_buf, message_buf_len);
  EVP_DigestFinal(mdctx2, hash_out, NULL);

  //Params_rand_exponent(params, sk);
  BN_bin2bn(hash_out, 32, hash_bn);
  BN_mod(hash_bn, hash_bn, Params_order(params), ctx);
  Params_rand_point_exp(params, R, r);
  r_inv = BN_mod_inverse(NULL, r, Params_order(params), ctx);
  EC_POINT_get_affine_coordinates_GFp(Params_group(params), R, x_coord, y_coord, NULL);
  BN_mod_mul(val, x_coord, sk, Params_order(params), ctx);
  BN_mod_add(val, hash_bn, val, Params_order(params), ctx);
  BN_mod_mul(out, r_inv, val, Params_order(params), ctx);

  /* Output signature. */
  *sig_len = 32 + 32;
  *sig_out = (uint8_t *)malloc(*sig_len);
  memset(*sig_out, 0, 64);
  BN_bn2bin(x_coord, *sig_out + 32 - BN_num_bytes(x_coord)); 
  BN_bn2bin(out, *sig_out + 64 - BN_num_bytes(out));

  // Check verifies
  Params_exp(params, pk, sk);
  if (ECDSAVerify(pk, message_buf, message_buf_len, *sig_out, params) == 0) {
    printf("ERROR: produced signature that didn't verify\n");
  }

  BN_free(out);
  BN_free(hash_bn);
  BN_free(val);
  BN_free(r);
  BN_free(r_inv);
  BN_free(x_coord);
  BN_free(y_coord);
  EVP_MD_CTX_destroy(mdctx2);
  EC_POINT_free(R);
}

bool ECDSAVerify(const EC_POINT *pk, uint8_t *message_buf, int message_buf_len, uint8_t *signature, Params params) {
  uint8_t hash_out[SHA256_DIGEST_LENGTH];
  BIGNUM *hash_bn = BN_new();
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, message_buf, message_buf_len);
  EVP_DigestFinal(mdctx, hash_out, NULL);

  BN_bin2bn(hash_out, 32, hash_bn);
  BN_mod(hash_bn, hash_bn, Params_order(params), Params_ctx(params));

  BIGNUM *r = BN_new();
  BN_bin2bn(signature, 32, r);
  BIGNUM *s = BN_new();
  BN_bin2bn(signature + 32, 32, s);

  bool res = ECDSAVerify(pk, hash_bn, r, s, params);
  EVP_MD_CTX_destroy(mdctx);
  BN_free(r);
  BN_free(s);
  return res;
}
 

bool ECDSAVerify(const EC_POINT *pk, BIGNUM *m, BIGNUM *r, BIGNUM *s, Params params) {
    EC_POINT *test = EC_POINT_new(Params_group(params));
    EC_POINT *g_m = EC_POINT_new(Params_group(params));
    BN_CTX *ctx = Params_ctx(params);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *s_inv = BN_mod_inverse(NULL, s, Params_order(params), ctx);
    Params_exp(params, g_m, m);
    Params_exp_base(params, test, pk, r);
    Params_mul(params, test, test, g_m);
    Params_exp_base(params, test, test, s_inv);
    EC_POINT_get_affine_coordinates_GFp(Params_group(params), test, x, y, ctx);
    bool res = BN_cmp(x, r);
    if (res != 0) {
        printf("x = %s\n", BN_bn2hex(x));
        printf("y = %s\n", BN_bn2hex(y));
        printf("r = %s\n", BN_bn2hex(r));
        printf("s = %s\n", BN_bn2hex(s));
    }

    EC_POINT_free(test);
    EC_POINT_free(g_m);
    BN_free(x);
    BN_free(y);
    BN_free(s_inv);
    return res == 0;
}
