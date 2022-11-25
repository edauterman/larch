#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <string.h>

#include "params.h"
#include "ddh_proof.h"

DDHProof::DDHProof(int n_in) {
    n = n_in;
    c = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
    r = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
}

BIGNUM *HashView(int n, EC_POINT **g, EC_POINT **y, EC_POINT **t, Params params) {
    int offset = 3 * 33;
    uint8_t *buf = (uint8_t *)malloc(offset * n);
    uint8_t out_buf[SHA256_DIGEST_LENGTH];
    memset(buf, 0, offset * n);
    for (int i = 0; i < n; i++) {
        EC_POINT_point2oct(params->group, g[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i), 33, params->ctx);
        EC_POINT_point2oct(params->group, y[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33, 33, params->ctx);
        EC_POINT_point2oct(params->group, t[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33, 33, params->ctx);
    }
    hash_to_bytes(out_buf, SHA256_DIGEST_LENGTH, (const uint8_t *)buf, offset * n);
    BIGNUM *out_bn = BN_bin2bn(out_buf, SHA256_DIGEST_LENGTH, NULL);
    return out_bn;
}

// n is number of bases and vals, g_idx^x = y_idx
DDHProof *DDHProve(int n, int idx, BIGNUM *x, EC_POINT **g, EC_POINT **y, Params params) {
    BIGNUM **v = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
    BIGNUM **w = (BIGNUM **)malloc(n * sizeof(BIGNUM *));
    EC_POINT **t = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    DDHProof *proof = new DDHProof(n);
    for (int i = 0; i < n; i++) {
        v[i] = BN_new();
        Params_rand_exponent(params, v[i]);
        // don't use w[i] for i == idx
        if (i != idx) {
            w[i] = BN_new();
            Params_rand_exponent(params, w[i]);
        }
        t[i] = EC_POINT_new(params->group);
        if (i == idx) {
            // t_i = g_idx^{v_idx}
            Params_exp_base(params, t[i], g[i], v[i]);
        } else {
            // t_i = y_i^{w_i} g_i^{v_i}
            Params_exp_base2(params, t[i], y[i], w[i], g[i], v[i]);
        }
    }
    // c = H(g_1, y_1, ..., g_n, y_n, t_1, ... t_n)
    BIGNUM *c = HashView(n, g, y, t, params);
    // c_i = w_i
    BIGNUM *sum = BN_new();
    BN_zero(sum);
    for (int i = 0; i < n; i++) {
        if (i != idx) {
            proof->c[i] = w[i];
            BN_mod_add(sum, sum, w[i], params->order, params->ctx);
        }
    }
    // c_idx = c - \sum i=1 to n, i != idx, w_i
    proof->c[idx] = BN_new();
    BN_mod_sub(proof->c[idx], c, sum, params->order, params->ctx);
   
    // r_i = v_i
    for (int i = 0; i < n; i++) {
        if (i != idx) {
            proof->r[i] = v[i];
        }
    }
    // r_idx = v_idx - c_idx.x
    proof->r[idx] = BN_new();
    BN_mod_mul(proof->r[idx], proof->c[idx], x, params->order, params->ctx);
    BN_mod_sub(proof->r[idx], v[idx], proof->r[idx], params->order, params->ctx); 
    // free
    free(v);
    free(w);
    for (int i = 0; i < n; i++) {
        EC_POINT_free(t[i]);
    }
    free(t);
    return proof;
}

bool DDHVerify(DDHProof *proof, EC_POINT **g, EC_POINT **y, Params params) {
    int n = proof->n;
    EC_POINT **t = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    for (int i = 0; i < n; i++) {
        t[i] = EC_POINT_new(params->group);
        Params_exp_base2(params, t[i], y[i], proof->c[i], g[i], proof->r[i]);
    }
    BIGNUM *c = HashView(n, g, y, t, params);
    BIGNUM *sum = BN_new();
    BN_zero(sum);
    for (int i = 0; i < n; i++) {
        BN_mod_add(sum, proof->c[i], sum, params->order, params->ctx);
    
    }
    // free
    for (int i = 0; i < n; i++) {
        EC_POINT_free(t[i]);
    }
    free(t);
    return BN_cmp(sum, c);
}
