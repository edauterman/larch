#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../src/ddh_proof.h"

using namespace std;

bool CorrectProof() {
    Params params = Params_new(P256);
    EC_POINT *base1 = EC_POINT_new(Params_group(params));
    EC_POINT *base2 = EC_POINT_new(Params_group(params));
    EC_POINT *S1 = EC_POINT_new(Params_group(params));
    EC_POINT *S2 = EC_POINT_new(Params_group(params));
    BIGNUM *x = BN_new();
    Params_rand_point(params, base1);
    Params_rand_point(params, base2);
    Params_exp_base(params, S1, base1, x);
    Params_exp_base(params, S2, base2, x);
    DDHProof *proof = Prove(params, base1, base2, x);
    bool res = Verify(params, proof, base1, base2, S1, S2);
    if (res) {
        cout << "Test successfull" << endl;
    } else {
        cout << "ERROR: correct proof failed to validate" << endl;
    }
    EC_POINT_free(base1);
    EC_POINT_free(base2);
    EC_POINT_free(S1);
    EC_POINT_free(S2);
    BN_free(x);
    return res;
}

int main() {
    CorrectProof();
}
