#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../src/or_groth.h"

using namespace std;

bool CorrectProof() {
    int log_len = 2;
    int len = 1 << log_len;
    int idx = 0;
    EC_POINT **cms = (EC_POINT **)malloc(len * sizeof(EC_POINT *));
    BIGNUM *x = BN_new();
    BIGNUM *open = BN_new();
    Params params = Params_new(P256);
    //EC_POINT *h = EC_POINT_dup(Params_h(params), Params_group(params));
    EC_POINT *h = EC_POINT_new(Params_group(params));
    Params_rand_point(params, h);
    for (int i = 0; i < len; i++) {
        cms[i] = EC_POINT_new(params->group);
        if (i == idx) {
            BN_zero(x);
            Params_rand_exponent(params, open);
            Params_com(params, h, cms[i], x, open);
        } else {
            Params_rand_point(params, cms[i]);
        }
    }
    OrProof *proof = Prove(params, h, cms, idx, len, log_len, open);
    bool res = Verify(params, h, proof, cms, len, log_len);
    if (res) {
        cout << "Test successfull" << endl;
    } else {
        cout << "ERROR: correct proof failed to validate" << endl;
    }
    for (int i = 0; i < len; i++) {
        EC_POINT_free(cms[i]);
    }
    free(cms);
    BN_free(x);
    BN_free(open);
    return res;
}

bool SerializeTest() {
    int log_len = 2;
    int len = 1 << log_len;
    int idx = 0;
    EC_POINT **cms = (EC_POINT **)malloc(len * sizeof(EC_POINT *));
    BIGNUM *x = BN_new();
    BIGNUM *open = BN_new();
    Params params = Params_new(P256);
    //EC_POINT *h = EC_POINT_dup(Params_h(params), Params_group(params));
    EC_POINT *h = EC_POINT_new(Params_group(params));
    Params_rand_point(params, h);
    for (int i = 0; i < len; i++) {
        cms[i] = EC_POINT_new(params->group);
        if (i == idx) {
            BN_zero(x);
            Params_rand_exponent(params, open);
            Params_com(params, h, cms[i], x, open);
        } else {
            Params_rand_point(params, cms[i]);
        }
    }
    OrProof *proof = Prove(params, h, cms, idx, len, log_len, open);
    uint8_t *buf;
    int len_test;
    proof->Serialize(params, &buf, &len_test);
    OrProof *proof2 = new OrProof();
    proof2->Deserialize(params, buf);
    bool res = Verify(params, h, proof2, cms, len, log_len);
    if (res) {
        cout << "Test successfull" << endl;
    } else {
        cout << "ERROR: correct proof failed to validate" << endl;
    }
    for (int i = 0; i < len; i++) {
        EC_POINT_free(cms[i]);
    }
    free(cms);
    BN_free(x);
    BN_free(open);
    return res;
}

int main() {
    CorrectProof();
    SerializeTest();
}
