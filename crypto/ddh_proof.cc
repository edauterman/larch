#include <openssl/evp.h>
#include <openssl/sha.h>

#include "params.h"
#include "ddh_proof.h"

DDHProof::DDHProof(int n) {
    // Allocate array but not BNs
}

BIGNUM *HashView(int n, EC_POINT **g, EC_POINT **y, EC_POINT **t) {
    int offset = 3 * 33;
    uint8_t *buf = (uint8_t *)malloc(offset * n);
    uint8_t out_buf[SHA256_DIGEST_LENGTH];
    memset(buf, 0, offset * n);
    for (int i = 0; i < n; i++) {
        EC_POINT_point2oct(params->group, g[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i), 33, params->ctx);
        EC_POINT_point2oct(params->group, y[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33, 33, params->ctx);
        EC_POINT_point2oct(params->group, t[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33, 33, params->ctx);
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, buf, offset * n);
    EVP_DigestFinal_ex(mdctx, out_buf, NULL);
    BIGNUM *out_bn = BN_bin2bn(out_buf, SHA256_DIGEST_LENGTH, NULL);
    return out_bn;
}

// n is number of bases and vals, g_idx^x = y_idx
DDHProof DDHProver::Prove(int n, int idx, BIGNUM *x, EC_POINT **g, EC_POINT **y) {
    BIGNUM **v = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
    BIGNUM **w = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
    EC_POINT **t = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    DDHProof *proof = new DDHProof(n);
    for (int i = 0; i < n; i++) {
        v[i] = BN_new();
        Params_rand_exponent(params, v[i]);
        // don't use w[i] for i == idx
        w[i] = BN_new();
        Params_rand_exponent(params, w[i]);
        t[i] = EC_POINT_new();
        if (i == idx) {
            // t_i = g_idx^{v_idx}
            Params_exp_base(params, t[i], g[i], v[i]);
        } else {
            // t_i = y_i^{w_i} g_i^{v_i}
            Params_exp_base2(params, t[i], y[i], w[i], g[i], v[i]);
        }
    }
    // c = H(g_1, y_1, ..., g_n, y_n, t_1, ... t_n)
    BIGNUM *c = HashView(n, g, y, t);
    // c_i = w_i
    BIGNUM *sum = BN_new();
    BN_zero(sum);
    for (int i = 0; i < n; i++) {
        if (i != idx) {
            proof->c[i] = w[i];
            BN_mod_add(sum, w[i], params->order);
        }
    }
    // c_idx = c - \sum i=1 to n, i != idx, w_i
    BN_new(proof->c[idx]);
    BN_mod_sub(proof->c[idx], c, sum, params->order, params->ctx);
   
    // r_i = v_i
    for (int i = 0; i < n; i++) {
        if (i != idx) {
            proof->r[i] = v[i];
        }
    }
    // r_idx = v_idx - c_idx.x
    BN_new(proof->r[idx]);
    BN_mod_mul(proof->r[idx], proof->c[idx], x, params->order, params->ctx);
    BN_mod_sub(proof->r[idx], v[idx], proof->r[idx], params->order, params->ctx); 
    // TODO free
    return proof;
}

bool DDHVerifier::Verify(int n, DDHProof *proof, EC_POINT **g, EC_POINT **y) {
    EC_POINT **t = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    for (int i = 0; i < n; i++) {
        t[i] = EC_POINT_new();
        Params_exp_base2(params, t[i], y[i], params->c[i], g[i], params->r[i]);
    }
    BIGNUM *c = HashView(n, g, y, t);
    BIGNUM *sum = BN_new();
    BN_zero(sum);
    for (int i = 0; i < n; i++) {
        BN_mod_add(sum, params->c[i], sum, params->order);
    
    }
    // TODO free
    return BN_cmp(sum, c);
}
