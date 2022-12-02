#include <openssl/bn.h>
#include <openssl/ec.h>
#include <cmath>
#include <vector>

#include "params.h"
#include "or_groth.h"
#include "ddh_proof.h"
#include "pw.h"

using namespace std;

EC_POINT **ComputeCms(Params params, vector<EC_POINT *>bases_inv, EC_POINT *C, int *log_len) {
    *log_len = ceil(log2(bases_inv.size()));
    int len = 1 << *log_len;
    EC_POINT **res = (EC_POINT **)malloc(len * sizeof(EC_POINT *));
    for (int i = 0; i < bases_inv.size(); i++) {
        Params_mul(params, res[i], bases_inv[i], C);
    }
    for (int i = bases_inv.size(); i < len; i++) {
        Params_rand_point(params, res[i]);
    }
}

ElGamalCt::ElGamalCt(Params params) {
    R = EC_POINT_new(Params_group(params));
    C = EC_POINT_new(Params_group(params));
}

PasswordClient::PasswordClient() {
    params = Params_new(P256);
}

PasswordLog::PasswordLog() {
    params = Params_new(P256);
}

EC_POINT *PasswordClient::StartEnroll() {
    x = BN_new();
    Params_rand_exponent(params, x);
    X = EC_POINT_new(Params_group(params));
    Params_exp(params, X, x);
    return EC_POINT_dup(X, Params_group(params));
}

EC_POINT *PasswordLog::Enroll(EC_POINT *X_in) {
    X = X_in;
    sk = BN_new();
    Params_rand_exponent(params, sk);
    EC_POINT *recover_pt = EC_POINT_new(Params_group(params));
    Params_exp_base(params, recover_pt, X, sk);
    return recover_pt;
}

void PasswordClient::FinishEnroll(EC_POINT *recover_pt_in) {
    recover_pt = recover_pt_in;
}

EC_POINT *PasswordClient::StartRegister(uint8_t *id, int len) {
    EC_POINT *hash_id = EC_POINT_new(Params_group(params));
    Params_hash_to_point(params, hash_id, id, len);
    EC_POINT *base_inv = EC_POINT_new(Params_group(params));
    Params_inv(params, base_inv, hash_id);
    bases_inv.push_back(base_inv);
    EC_POINT_free(hash_id);
    return base_inv;
}

EC_POINT *PasswordLog::Register(uint8_t *id, int len, EC_POINT *base_inv) {
    bases_inv.push_back(base_inv);
    EC_POINT *hash_pt = EC_POINT_new(Params_group(params));
    Params_hash_to_point(params, hash_pt, id, len);
    Params_exp_base(params, hash_pt, hash_pt, sk);
    return hash_pt;
}

void PasswordClient::FinishRegister(EC_POINT *in, EC_POINT *pw) {
    EC_POINT *neg_in = EC_POINT_new(Params_group(params));
    Params_inv(params, neg_in, in);
    EC_POINT *client_share = EC_POINT_new(Params_group(params));
    Params_mul(params, client_share, neg_in, pw);
    client_shares.push_back(client_share); 
}

void PasswordClient::StartAuth(uint8_t *id, int len, ElGamalCt *ct, OrProof *or_proof, DDHProof *ddh_proof, BIGNUM *r) {
    EC_POINT *hash_id = EC_POINT_new(Params_group(params));
    Params_hash_to_point(params, hash_id, id, len);
    Params_rand_exponent(params, r);
    EC_POINT *m = EC_POINT_new(Params_group(params));
    Params_exp_base(params, ct->C, X, r);
    Params_mul(params, ct->C, ct->C, m);
    Params_exp(params, ct->R, r);
    // TODO OrProof and DDHProof
    
    EC_POINT_free(hash_id);
    EC_POINT_free(m);
}

EC_POINT *PasswordLog::Auth(ElGamalCt *ct, OrProof *or_proof, DDHProof *ddh_proof) {
    double precise_log = log2(bases_inv.size());
    int log_len;
    EC_POINT **cms = ComputeCms(params, bases_inv, ct->C, &log_len);
    int len = 1 << log_len;
    // Verify OrProof
    // Verify DDHProof
    EC_POINT *out = EC_POINT_new(Params_group(params));
    // TODO free cms
    Params_exp_base(params, out, ct->C, sk);
    return out;
}

EC_POINT *PasswordClient::FinishAuth(int register_idx, EC_POINT *in, BIGNUM *r) {
    EC_POINT *tmp = EC_POINT_new(Params_group(params));
    BIGNUM *neg_r = BN_new();
    EC_POINT *out = EC_POINT_new(Params_group(params));
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BN_mod_sub(neg_r, zero, r, Params_order(params), Params_ctx(params));
    Params_exp_base(params, tmp, recover_pt, neg_r);
    Params_mul(params, out, in, tmp);
    Params_mul(params, out, out, client_shares[register_idx]);

    EC_POINT_free(tmp);
    BN_free(neg_r);
    BN_free(zero);
    return out;
}
