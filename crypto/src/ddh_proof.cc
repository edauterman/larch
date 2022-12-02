#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"
#include "ddh_proof.h"

DDHProof::DDHProof(BIGNUM *c_in, BIGNUM *v_in) {
    c = c_in;
    v = v_in;
}

BIGNUM *HashTranscript(Params params, EC_POINT *base1, EC_POINT *base2, EC_POINT *R1, EC_POINT *R2) {
    uint8_t buf[33 * 4];
    EC_POINT_point2oct(Params_group(params), base1, POINT_CONVERSION_COMPRESSED, buf, 33, Params_ctx(params));
    EC_POINT_point2oct(Params_group(params), base2, POINT_CONVERSION_COMPRESSED, buf + 33, 33, Params_ctx(params));
    EC_POINT_point2oct(Params_group(params), R1, POINT_CONVERSION_COMPRESSED, buf + 2 * 33, 33, Params_ctx(params));
    EC_POINT_point2oct(Params_group(params), R2, POINT_CONVERSION_COMPRESSED, buf + 3 * 33, 33, Params_ctx(params));
    BIGNUM *res = BN_new();
    Params_hash_to_exponent(params, res, buf, 33 * 4);
    return res;
}

// Prove S1 = base1^x and S2 = base2^x use same x
DDHProof *Prove(Params params, EC_POINT *base1, EC_POINT *base2, BIGNUM *x) {
    BIGNUM *r = BN_new();
    Params_rand_exponent(params, r);
    EC_POINT *R1 = EC_POINT_new(Params_group(params));
    EC_POINT *R2 = EC_POINT_new(Params_group(params));
    Params_exp_base(params, R1, base1, r);
    Params_exp_base(params, R2, base1, r);
    BIGNUM *c = HashTranscript(params, base1, base2, R1, R2);
    BIGNUM *v = BN_new();
    BN_mod_mul(v, c, x, Params_order(params), Params_ctx(params));
    BN_mod_sub(v, r, v, Params_order(params), Params_ctx(params));
    EC_POINT_free(R1);
    EC_POINT_free(R2);
    BN_free(r);
    return new DDHProof(c,v);
}

bool Verify(Params params, DDHProof *proof, EC_POINT *base1, EC_POINT *base2, EC_POINT *S1, EC_POINT *S2) {
    EC_POINT *R1 = EC_POINT_new(Params_group(params));
    EC_POINT *R2 = EC_POINT_new(Params_group(params));
    Params_exp_base2(params, R1, base1, proof->v, S1, proof->c);
    Params_exp_base2(params, R2, base2, proof->v, S2, proof->c);
    BIGNUM *c_test = HashTranscript(params, base1, base2, R1, R2);
    bool res = !BN_cmp(proof->c, c_test);
    EC_POINT_free(R1);
    EC_POINT_free(R2);
    BN_free(c_test);
    return res;
}
