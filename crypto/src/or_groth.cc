#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"
        
OrProof::OrProof(BIGNUM **c_l, BIGNUM **c_a, BIGNUM **c_b, BIGNUM **c_d, BIGNUM **f, BIGNUM **z_a, BIGNUM **z_b, BIGNUM *z_d, int len, int log_len) : c_l(c_l), c_a(c_a), c_b(c_b), c_d(c_d), f(f), z_a(z_a), z_b(z_b), z_d(z_d), len(len), log_len(log_len) {}

void HashTranscript(Params params, int log_len, EC_POINT **c_l, EC_POINT **c_a, EC_POINT **c_b, EC_POINT **c_d, uint8_t *digest) {
    uint8_t *buf = (uint8_t *)malloc(33 * 4 * log_len);
    int offset = 33 * 4;
    for (int i = 0; i < log_len; i++) {
        EC_POINT_point2oct(Params_group(params), c_l[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i), 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_a[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33, 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_b[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33, 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_d[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33 + 33, 33, Params_ctx(params));
    }
    hash_to_bytes(digest, SHA256_DIGEST_LENGTH, buf, offset * log_len);
    free(buf);
}

OrProof *Prove(Params params, EC_POINT **cms, int idx, int len, int log_len, BIGNUM *open) {
    BIGNUM **r = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **a = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **s = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **t = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **phi = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    EC_POINT **c_l = (EC_POINT **)malloc(sizeof(EC_POINT *) * log_len);
    EC_POINT **c_a = (EC_POINT **)malloc(sizeof(EC_POINT *) * log_len);
    EC_POINT **c_b = (EC_POINT **)malloc(sizeof(EC_POINT *) * log_len);
    EC_POINT **c_d = (EC_POINT **)malloc(sizeof(EC_POINT *) * log_len);
    BIGNUM *tmp = BN_new();
    BIGNUM *zero = BN_new();
    EC_POINT *tmp_cm = EC_POINT_new(Params_group(params));
    BN_zero(zero);
    BIGNUM ***p = (BIGNUM ***)malloc(sizeof(BIGNUM **) * len);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    BIGNUM **l = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **l_inv = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);

    BIGNUM **f = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **z_a = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM **z_b = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
    BIGNUM *z_d = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *x_pow = BN_new();

    for (int i = 0; i < log_len; i++) {
        int bit = (idx & (1 << i)) >> i;
        l[i] = BN_new();
        l_inv[i] = BN_new();
        if (bit == 1) {
            BN_one(l[i]);
            BN_zero(l_inv[i]);
        } else {
            BN_zero(l[i]);
            BN_one(l_inv[i]);
        }
    }

    for (int i = 0; i < log_len; i++) {
        r[i] = BN_new();
        a[i] = BN_new();
        s[i] = BN_new();
        t[i] = BN_new();
        phi[i] = BN_new();
        c_l[i] = EC_POINT_new(Params_group(params));
        c_a[i] = EC_POINT_new(Params_group(params));
        c_b[i] = EC_POINT_new(Params_group(params));
        c_d[i] = EC_POINT_new(Params_group(params));

        Params_rand_exp(params, r[i]);
        Params_rand_exp(params, a[i]);
        Params_rand_exp(params, s[i]);
        Params_rand_exp(params, t[i]);
        Params_rand_exp(params, phi[i]);

        Params_com(params, c_l[i], l[i], r[i]);
        Params_com(params, c_a[i], a[i], s[i]);
        BN_mod_mul(tmp, a[i], l[i], Params_order(params), Params_ctx(params));
        Params_com(params, c_b[i], tmp, t[i]);
    }

    ShamirShare **shares = (ShamirShare **)malloc(sizeof(ShamirShare *) * log_len);
    for (int i = 0; i < len; i++) {
        p[i] = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
        for (int j = 0; j < log_len; j++) {
            p[i][j] = BN_new();
        }
        for (int j = 0; j < log_len; j++) {
            shares[j] = ShamirShare_new();
            BN_zero(shares[j]->y);
            int i_j = (i & (1 << j)) >> j;
            if (i_j == 0) {
                BN_mod_mul(shares[j]->x, a[j], l_inv[j], Params_order(params));
            } else if (i_j == 1) {
                BN_mod_mul(shares[j]->x, a[j], l[j], Params_order(params));
            }
        }
        getCoefficients(log_len, log_len, shares, Params_order(params), p[i], Params_ctx(params));
        for (int j = 0; j < log_len; j++) {
            ShamirShare_free(shares[j]);
        }
    }

    for (int i = 0; i < log_len; i++) {
        Params_com(params, c_d[i], zero, phi[i]);
        for (int j = 0; j < len; j++) {
            Params_exp_base(params, tmp_g, cms[j], p[j][i]);
            Params_mul(params, c_d[i], c_d[i], tmp_g);
        }
    }

    HashTranscript(params, log_len, c_l, c_a, c_b, c_d, digest);
    BN_bin2bn(digest, 32, x);
    BN_mod(x, x, Params_order(params));

    BN_zero(z_d);
    BN_one(x_pow);
    for (int i = 0; i < log_len; i++) {
        f[i] = BN_new();
        z_a[i] = BN_new();
        z_b[i] = BN_new();

        // f_i = l_i . x + a_i
        BN_mod_mul(f[i], l[i], x, Params_order(params));
        BN_mod_add(f[i], f[i], a[i], Params_order(params));

        //z_a_i = r_i . x + s_i
        BN_mod_mul(z_a[i], r[i], x, Params_order(params));
        BN_mod_add(z_a[i], z_a[i], s[i], Params_order(params));

        //z_b_i = r_i . (x - f_i) + t_i
        BN_mod_sub(z_b[i], x, f[i], Params_order(params));
        BN_mod_mul(z_b[i], z_b[i], r[i], Params_order(params));
        BN_mod_add(z_b[i], z_b[i], t[i], Params_order(params));

        BN_mod_mul(tmp, phi[i], x_pow, Params_order(params));
        BN_mod_add(z_d, z_d, tmp, Params_order(params));
        BN_mod_mul(x_pow, x_pow, x, Params_order(params));
    }

    BN_mod_mul(tmp, open, x_pow, Params_order(params));
    BN_mod_sub(z_d, tmp, z_d, Params_order(params));

    BN_free(tmp);
    BN_free(zero);
    BN_free(x);
    BN_free(x_pow);
    EC_POINT_free(tmp_cm);

    for (int i = 0; i < log_len; i++) {
        BN_free(r[i]);
        BN_free(a[i]);
        BN_free(s[i]);
        BN_free(t[i]);
        BN_free(phi[i]);
        BN_free(l[i]);
        BN_free(l_inv[i]);
    }
    free(r);
    free(a);
    free(s);
    free(t);
    free(phi);
    free(l);
    free(l_iv);
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < log_len; j++) {
            BN_free(p[i][j]);
        }
        free(p[i]);
    }
    free(p);

    return new OrProof(c_l, c_a, c_b, c_d, f, z_a, z_b, z_d, len, log_len);
}

bool Verify(Params params, OrProof *proof, EC_POINT **cms, int len, int log_len) {
    BIGNUM *x = BN_new();
    HashTranscript(params, log_len, proof->c_l, proof->c_a, proof->c_b, proof->c_d, digest);
    BN_bin2bn(digest, 32, x);
    BN_mod(x, x, Params_order(params));

    EC_POINT *check1 = EC_POINT_new(Params_group(params));
    EC_POINT *check2 = EC_POINT_new(Params_group(params));
    BIGNUM *tmp = BN_new();
    BIGNUM *x_pow = BN_new();
    BIGNUM *x_pow_inv = BN_new();
    BIGNUM *prod = BN_new();
    EC_POINT *term1 = EC_POINT_new(Params_group(params));
    EC_POINT *term2 = EC_POINT_new(Params_group(params));
    EC_POINT *tmp_g = EC_POINT_new(Params_group(params));

    for (int i = 0; i < log_len; i++) {
        // c_l[i]^x . c_a[i] ?= Commit(f[i], z_a[i])
        Params_exp_base(params, check1, c_l[i], x);
        Params_mul(params, check1, check1, c_a[i]);
        Params_com(params, check2, f[i], z_a[i]);
        if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
            return false;
        }

        // c_l[i]^{x-f[i]} . c_b[i] ?= Commit(0, z_b[i])
        BN_mod_sub(tmp, x, f[i], Params_order(params), Params_ctx(params));
        Params_exp_base(params, check1, c_l[i], tmp);
        Params_mul(params, check1, check1, c_b[i]);
        Params_exp_base_h(params, check2, z_b[i]);
        if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
            return false;
        }
    }

    EC_POINT_copy(term1, Params_g(params));
    for (int i = 0; i < len; i++) {
        BN_one(prod);
        for (int j = 0; j < log_len; j++) {
            int bit = (i & (1 << j)) >> j;
            if (bit == 1) {
                BN_mod_mul(prod, prod, f[j], Params_order(params), Params_ctx(params));
            } else {
                BN_mod_sub(tmp, x, f[j], Params_order(params), Params_ctx(params));
                BN_mod_mul(prod, prod, tmp, Params_order(params), Params_ctx(params));
            }
        }
        Params_exp_base(params, tmp_g, cms[i], prod);
        Params_mul(params, term1, term1, tmp_g);
    }

    BN_one(x_pow);
    EC_POINT_copy(term2, Params_g(params));
    for (int i = 0; i < log_len; i++) {
        BN_mod_inverse(x_pow_inv, x_power, Params_order(params), Params_ctx(params));
        Params_exp_base(params, tmp_g, c_d[i], x_pow_inv);
        Params_mul(params, term2, term2, tmp_g);
        BN_mod_mul(x_pow, x_pow, x, Params_order(params), Params_ctx(params));
    }
    Params_mul(params, check1, term1, term2);
    Params_exp_base_h(params, check2, z_d);
    if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
        return false;
    }

    // TODO return false should exit to cleanup first
    EC_POINT_free(check1);
    EC_POINT_free(check2);
    EC_POINT_free(term1);
    EC_POINT_free(term2);
    EC_POINT_free(tmp_g);
    BN_free(tmp);
    BN_free(x_pow);
    BN_free(x_pow_inv);
    BN_free(prod);
    BN_free(x);

    return true;

}
