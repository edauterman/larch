#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <vector>

#include "sigs.h"
#include "params.h"

ShortHint::ShortHint(BIGNUM *xcoord_in) : xcoord(xcoord_in) {}

Hint::Hint() {}

Hint::Hint(BIGNUM *xcoord_in, BIGNUM *auth_r_in, BIGNUM *c_in, BIGNUM *f_in, BIGNUM *g_in, BIGNUM *h_in) : xcoord(xcoord_in), auth_r(auth_r_in), c(c_in), f(f_in), g(g_in), h(h_in) {}

void GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret, Params params) {
    uint8_t pt[16];
    uint8_t out[16];
    int len;
    memset(pt, 0, 16);
    memcpy(pt, (uint8_t *)&ctr, sizeof(uint64_t));
    EVP_EncryptUpdate(ctx, out, &len, pt, 16);
    BN_bin2bn(out, len, ret);
    BN_mod(ret, ret, Params_order(params), bn_ctx);
}

void GetPreprocessValue(uint64_t ctr, BIGNUM *ret, uint8_t *seed_in, Params params) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t iv[16];
    memset(iv, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed_in, iv);
    GetPreprocessValue(ctx, bn_ctx, ctr, ret, params);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (bn_ctx) BN_CTX_free(bn_ctx);
}
