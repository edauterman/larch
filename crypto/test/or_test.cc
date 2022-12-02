#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../src/or_groth.h"

using namespace std;

bool CorrectProof() {
    int log_len = 4;
    int len = 1 << log_len;
    int idx = 0;
    EC_POINT **cms = (EC_POINT **)malloc(len * sizeof(EC_POINT *));
    BIGNUM *x = BN_new();
    BIGNUM *open = BN_new();
    Params params = Params_new(P256);
    for (int i = 0; i < len; i++) {
        cms[i] = EC_POINT_new(params->group);
        if (i == idx) {
            BN_zero(x);
            Params_rand_exponent(params, open);
            Params_com(params, cms[i], x, open);
        } else {
            Params_rand_point(params, cms[i]);
        }
    }
    OrProof *proof = Prove(params, cms, idx, len, log_len, open);
    bool res = Verify(params, proof, cms, len, log_len);
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
}
