#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <vector>
#include <thread>
#include <string.h>

#include "params.h"
#include "or_groth.h"

using namespace std;
        
OrProof::OrProof() {}

OrProof::OrProof(EC_POINT **c_l, EC_POINT **c_a, EC_POINT **c_b, EC_POINT**c_d, BIGNUM **f, BIGNUM **z_a, BIGNUM **z_b, BIGNUM *z_d, int len, int log_len) : c_l(c_l), c_a(c_a), c_b(c_b), c_d(c_d), f(f), z_a(z_a), z_b(z_b), z_d(z_d), len(len), log_len(log_len) {}

void OrProof::Serialize(Params params, uint8_t **buf, int *len_in) {
    *len_in = (33 * 4 * log_len) + (32 * 3 * log_len) + 32 + sizeof(uint32_t);
    *buf = (uint8_t *)malloc(*len_in);
    memset(*buf, 0, *len_in);
    int offset = 0;
    uint32_t log_len_32 = log_len;
    memcpy(*buf, (uint8_t *)&log_len_32, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    for (int i = 0; i < log_len; i++) {
        EC_POINT_point2oct(Params_group(params), c_l[i], POINT_CONVERSION_COMPRESSED, *buf + offset, 33, Params_ctx(params));
        offset += 33;
        EC_POINT_point2oct(Params_group(params), c_a[i], POINT_CONVERSION_COMPRESSED, *buf + offset, 33, Params_ctx(params));
        offset += 33;
        EC_POINT_point2oct(Params_group(params), c_b[i], POINT_CONVERSION_COMPRESSED, *buf + offset, 33, Params_ctx(params));
        offset += 33;
        EC_POINT_point2oct(Params_group(params), c_d[i], POINT_CONVERSION_COMPRESSED, *buf + offset, 33, Params_ctx(params));
        offset += 33;
        BN_bn2bin(f[i], *buf + offset + 32 - BN_num_bytes(f[i]));
        offset += 32;
        BN_bn2bin(z_a[i], *buf + offset + 32 - BN_num_bytes(z_a[i]));
        offset += 32;
        BN_bn2bin(z_b[i], *buf + offset + 32 - BN_num_bytes(z_b[i]));
        offset += 32;
    }
    BN_bn2bin(z_d, *buf + offset + 32 - BN_num_bytes(z_d));
}

void OrProof::Deserialize(Params params, const uint8_t *buf) {
    uint32_t log_len_read;
    memcpy((uint8_t *)&log_len_read, buf, sizeof(uint32_t));
    log_len = log_len_read;
    len = 1 << log_len;
    int offset = sizeof(uint32_t);
    c_l = (EC_POINT **)malloc(log_len * sizeof(EC_POINT *));
    c_a = (EC_POINT **)malloc(log_len * sizeof(EC_POINT *));
    c_b = (EC_POINT **)malloc(log_len * sizeof(EC_POINT *));
    c_d = (EC_POINT **)malloc(log_len * sizeof(EC_POINT *));
    f = (BIGNUM **)malloc(log_len * sizeof(BIGNUM *));
    z_a = (BIGNUM **)malloc(log_len * sizeof(BIGNUM *));
    z_b = (BIGNUM **)malloc(log_len * sizeof(BIGNUM *));
    for (int i = 0; i < log_len; i++) {
        c_l[i] = EC_POINT_new(Params_group(params));
        EC_POINT_oct2point(Params_group(params), c_l[i], buf + offset, 33, Params_ctx(params));
        offset += 33;
        c_a[i] = EC_POINT_new(Params_group(params));
        EC_POINT_oct2point(Params_group(params), c_a[i], buf + offset, 33, Params_ctx(params));
        offset += 33;
        c_b[i] = EC_POINT_new(Params_group(params));
        EC_POINT_oct2point(Params_group(params), c_b[i], buf + offset, 33, Params_ctx(params));
        offset += 33;
        c_d[i] = EC_POINT_new(Params_group(params));
        EC_POINT_oct2point(Params_group(params), c_d[i], buf + offset, 33, Params_ctx(params));
        offset += 33;
        f[i] = BN_new();
        BN_bin2bn(buf + offset, 32, f[i]);
        offset += 32;
        z_a[i] = BN_new();
        BN_bin2bn(buf + offset, 32, z_a[i]);
        offset += 32;
        z_b[i] = BN_new();
        BN_bin2bn(buf + offset, 32, z_b[i]);
        offset += 32;
    }
    z_d = BN_new();
    BN_bin2bn(buf + offset, 32, z_d);
}

vector<BIGNUM *> MultiplyTwoPolys(Params params, vector<BIGNUM *> long_poly, vector<BIGNUM *> deg1_poly) {
    vector<BIGNUM *> result;
    BIGNUM *tmp = BN_new();
    for (int i = 0; i < long_poly.size() + 1; i++) {
        result.push_back(BN_new());
        BN_zero(result[i]);
    }
    for (int i = 0; i < long_poly.size(); i++) {
        for (int j = 0; j < deg1_poly.size(); j++) {
            BN_mod_mul(tmp, long_poly[i], deg1_poly[j], Params_order(params), Params_ctx(params));
            BN_mod_add(result[i + j], result[i + j], tmp, Params_order(params), Params_ctx(params));
        }
    }
    return result;
}

vector<BIGNUM *> MultiplyManyPolys(Params params, vector<vector<BIGNUM *>> in) {
    vector<BIGNUM *> curr = in[0];
    for (int i = 1; i < in.size(); i++) {
        vector<BIGNUM *> res = MultiplyTwoPolys(params, curr, in[i]);
        if (i != 1) {
            for (int j = 0; j < curr.size(); j++) {
                BN_free(curr[j]);
            }
        }
        curr = res;
    }
    return curr;
}


void HashTranscript(Params params, int log_len, EC_POINT **c_l, EC_POINT **c_a, EC_POINT **c_b, EC_POINT **c_d, uint8_t *digest) {
    uint8_t *buf = (uint8_t *)malloc(33 * 4 * log_len);
    int offset = 33 * 4;
    memset(buf, 0, offset * log_len);
    for (int i = 0; i < log_len; i++) {
        EC_POINT_point2oct(Params_group(params), c_l[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i), 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_a[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33, 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_b[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33, 33, Params_ctx(params));
        EC_POINT_point2oct(Params_group(params), c_d[i], POINT_CONVERSION_COMPRESSED, buf + (offset * i) + 33 + 33 + 33, 33, Params_ctx(params));
    }
    hash_to_bytes(digest, SHA256_DIGEST_LENGTH, buf, offset * log_len);
    free(buf);
}

void proof_task(Params params, int start_j, int end_j, int log_len, EC_POINT *h, EC_POINT **cms, EC_POINT **c_d, BIGNUM **phi, BIGNUM ***p) {
    EC_POINT *tmp_g = EC_POINT_new(Params_group(params));
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    for (int i = 0; i < log_len; i++) {
        //Params_com(params, h, c_d[i], zero, phi[i]);
        for (int j = start_j; j < end_j; j++) {
            Params_exp_base(params, tmp_g, cms[j], p[j][i]);
            if (j == start_j) {
                EC_POINT_copy(c_d[i], tmp_g);
            } else {
                Params_mul(params, c_d[i], c_d[i], tmp_g);
            }
        }
    }
}

void OrProve(Params params, EC_POINT *h, EC_POINT **cms, int idx, int len, int log_len, BIGNUM *open, OrProof **proof) {
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
    BIGNUM *tmp2 = BN_new();
    BIGNUM *zero = BN_new();
    EC_POINT *tmp_cm = EC_POINT_new(Params_group(params));
    EC_POINT *tmp_g = EC_POINT_new(Params_group(params));
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

        Params_rand_exponent(params, r[i]);
        Params_rand_exponent(params, a[i]);
        Params_rand_exponent(params, s[i]);
        Params_rand_exponent(params, t[i]);
        Params_rand_exponent(params, phi[i]);

        Params_com(params, h, c_l[i], l[i], r[i]);
        Params_com(params, h, c_a[i], a[i], s[i]);
        BN_mod_mul(tmp, a[i], l[i], Params_order(params), Params_ctx(params));
        Params_com(params, h, c_b[i], tmp, t[i]);
    }

    for (int i = 0; i < len; i++) {
        p[i] = (BIGNUM **)malloc(sizeof(BIGNUM *) * log_len);
        vector<vector<BIGNUM *>> factored_poly;
        for (int j = 0; j < log_len; j++) {
            vector<BIGNUM *>factor;
            BIGNUM *t1 = BN_new();
            BIGNUM *t2 = BN_new();
            int i_j = (i & (1 << j)) >> j;
            if (i_j == 0) {
                BN_mod_sub(t1, zero, a[j], Params_order(params), Params_ctx(params));
                BN_copy(t2, l_inv[j]);
            } else if (i_j == 1) {
                BN_copy(t1, a[j]);
                BN_copy(t2, l[j]);
            }
            factor.push_back(t1);
            factor.push_back(t2);
            factored_poly.push_back(factor);
        }
        vector<BIGNUM *>out_poly = MultiplyManyPolys(params, factored_poly);
        for (int j = 0; j < log_len; j++) {
            p[i][j] = out_poly[j];
        }
    }
    
    EC_POINT **thread_c_d[4];
    for (int thread = 0; thread < 4; thread++) {
        thread_c_d[thread] = (EC_POINT **)malloc(log_len * sizeof(EC_POINT *));
        for (int i = 0; i < log_len; i++) {
            thread_c_d[thread][i] = EC_POINT_new(Params_group(params));
        }
    }

    int num_workers = 4;
    thread workers[4];
    Params thread_params[4];
    for (int i = 0; i < 4; i++) {
        thread_params[i] = Params_new(P256);
        workers[i] = thread(proof_task, thread_params[i], i * len/4, (i + 1) * len / 4, log_len, h, cms, thread_c_d[i], phi, p);
    }
    for (int i = 0; i < 4; i++) {
        workers[i].join();
        Params_free(thread_params[i]);
    }
    for (int i = 0; i < log_len; i++) {
        EC_POINT_copy(c_d[i], thread_c_d[0][i]);
        Params_com(params, h, c_d[i], zero, phi[i]);
        Params_mul(params, c_d[i], c_d[i], thread_c_d[0][i]);
        Params_mul(params, c_d[i], c_d[i], thread_c_d[1][i]);
        Params_mul(params, c_d[i], c_d[i], thread_c_d[2][i]);
        Params_mul(params, c_d[i], c_d[i], thread_c_d[3][i]);
        EC_POINT_free(thread_c_d[0][i]);
        EC_POINT_free(thread_c_d[1][i]);
        EC_POINT_free(thread_c_d[2][i]);
        EC_POINT_free(thread_c_d[3][i]);
    }
    free(thread_c_d[0]);
    free(thread_c_d[1]);
    free(thread_c_d[2]);
    free(thread_c_d[3]);

    HashTranscript(params, log_len, c_l, c_a, c_b, c_d, digest);
    BN_bin2bn(digest, 32, x);
    BN_mod(x, x, Params_order(params), Params_ctx(params));

    BN_zero(z_d);
    BN_one(x_pow);
    for (int i = 0; i < log_len; i++) {
        f[i] = BN_new();
        z_a[i] = BN_new();
        z_b[i] = BN_new();

        // f_i = l_i . x + a_i
        BN_mod_mul(f[i], l[i], x, Params_order(params), Params_ctx(params));
        BN_mod_add(f[i], f[i], a[i], Params_order(params), Params_ctx(params));

        //z_a_i = r_i . x + s_i
        BN_mod_mul(z_a[i], r[i], x, Params_order(params), Params_ctx(params));
        BN_mod_add(z_a[i], z_a[i], s[i], Params_order(params), Params_ctx(params));

        //z_b_i = r_i . (x - f_i) + t_i
        BN_mod_sub(z_b[i], x, f[i], Params_order(params), Params_ctx(params));
        BN_mod_mul(z_b[i], z_b[i], r[i], Params_order(params), Params_ctx(params));
        BN_mod_add(z_b[i], z_b[i], t[i], Params_order(params), Params_ctx(params));

        BN_mod_mul(tmp, phi[i], x_pow, Params_order(params), Params_ctx(params));
        BN_mod_add(z_d, z_d, tmp, Params_order(params), Params_ctx(params));
        BN_mod_mul(x_pow, x_pow, x, Params_order(params), Params_ctx(params));
    }

    BN_mod_mul(tmp, open, x_pow, Params_order(params), Params_ctx(params));
    BN_mod_sub(z_d, tmp, z_d, Params_order(params), Params_ctx(params));

    BN_free(tmp);
    BN_free(tmp2);
    BN_free(zero);
    BN_free(x);
    BN_free(x_pow);
    EC_POINT_free(tmp_cm);
    EC_POINT_free(tmp_g);

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
    free(l_inv);
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < log_len; j++) {
            BN_free(p[i][j]);
        }
        free(p[i]);
    }
    free(p);

    *proof = new OrProof(c_l, c_a, c_b, c_d, f, z_a, z_b, z_d, len, log_len);
}

void OrVerify(Params params, EC_POINT *h, OrProof *proof, EC_POINT **cms, int len, int log_len, bool *res) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    BIGNUM *x = BN_new();
    HashTranscript(params, log_len, proof->c_l, proof->c_a, proof->c_b, proof->c_d, digest);
    BN_bin2bn(digest, 32, x);
    BN_mod(x, x, Params_order(params), Params_ctx(params));

    EC_POINT *check1 = EC_POINT_new(Params_group(params));
    EC_POINT *check2 = EC_POINT_new(Params_group(params));
    BIGNUM *tmp = BN_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *x_pow = BN_new();
    BIGNUM *x_pow_sub = BN_new();
    BIGNUM *prod = BN_new();
    EC_POINT *term1 = EC_POINT_new(Params_group(params));
    EC_POINT *term2 = EC_POINT_new(Params_group(params));
    EC_POINT *tmp_g = EC_POINT_new(Params_group(params));

    for (int i = 0; i < log_len; i++) {
        // c_l[i]^x . c_a[i] ?= Commit(f[i], z_a[i])
        Params_exp_base(params, check1, proof->c_l[i], x);
        Params_mul(params, check1, check1, proof->c_a[i]);
        Params_com(params, h, check2, proof->f[i], proof->z_a[i]);
        if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
            printf("First check failed, %d\n", i);
            *res = false;
            return;
        }

        // c_l[i]^{x-f[i]} . c_b[i] ?= Commit(0, z_b[i])
        BN_mod_sub(tmp, x, proof->f[i], Params_order(params), Params_ctx(params));
        Params_exp_base(params, check1, proof->c_l[i], tmp);
        Params_mul(params, check1, check1, proof->c_b[i]);
        Params_com(params, h, check2, zero, proof->z_b[i]);
        if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
            printf("Second check failed, %d\n", i);
            *res = false;
            return;
        }
    }

    for (int i = 0; i < len; i++) {
        BN_one(prod);
        for (int j = 0; j < log_len; j++) {
            int bit = (i & (1 << j)) >> j;
            if (bit == 1) {
                BN_mod_mul(prod, prod, proof->f[j], Params_order(params), Params_ctx(params));
            } else {
                BN_mod_sub(tmp, x, proof->f[j], Params_order(params), Params_ctx(params));
                BN_mod_mul(prod, prod, tmp, Params_order(params), Params_ctx(params));
            }
        }
        Params_exp_base(params, tmp_g, cms[i], prod);
        if (i > 0) {
            Params_mul(params, term1, term1, tmp_g);
        } else {
            EC_POINT_copy(term1, tmp_g);
        }
    }

    BN_one(x_pow);
    EC_POINT_copy(term2, Params_g(params));
    for (int i = 0; i < log_len; i++) {
        BN_mod_sub(x_pow_sub, zero, x_pow, Params_order(params), Params_ctx(params));
        Params_exp_base(params, tmp_g, proof->c_d[i], x_pow_sub);
        if (i > 0) {
            Params_mul(params, term2, term2, tmp_g);
        } else {
            EC_POINT_copy(term2, tmp_g);
        }
        BN_mod_mul(x_pow, x_pow, x, Params_order(params), Params_ctx(params));
    }
    Params_mul(params, check1, term1, term2);
    Params_com(params, h, check2, zero, proof->z_d);
    if (EC_POINT_cmp(Params_group(params), check1, check2, Params_ctx(params)) != 0) {
        printf("Last check failed :(\n");
        printf("check1 = %s\n", EC_POINT_point2hex(Params_group(params), check1, POINT_CONVERSION_COMPRESSED, Params_ctx(params)));
        printf("check2 = %s\n", EC_POINT_point2hex(Params_group(params), check2, POINT_CONVERSION_COMPRESSED, Params_ctx(params)));
        *res = false;
        return;
    }


    // TODO return false should exit to cleanup first
    EC_POINT_free(check1);
    EC_POINT_free(check2);
    EC_POINT_free(term1);
    EC_POINT_free(term2);
    EC_POINT_free(tmp_g);
    BN_free(tmp);
    BN_free(x_pow);
    BN_free(x_pow_sub);
    BN_free(prod);
    BN_free(x);

    *res = true;

}
