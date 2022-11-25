#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../src/ddh_proof.h"

using namespace std;

bool CorrectProof() {
    int n = 10;
    int idx = 0;
    EC_POINT **g = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    EC_POINT **y = (EC_POINT **)malloc(n * sizeof(EC_POINT *));
    BIGNUM *x = BN_new();
    Params params = Params_new(P256);
    for (int i = 0; i < n; i++) {
        g[i] = EC_POINT_new(params->group);
        y[i] = EC_POINT_new(params->group);
        Params_rand_point(params, g[i]);
        if (i == idx) {
            Params_rand_point_exp(params, y[i], x);
        } else {
            Params_rand_point(params, y[i]);
        }
    }
    DDHProof *proof = DDHProve(n, idx, x, g, y, params);
    bool res = DDHVerify(proof, g, y, params);
    if (res) {
        cout << "Test successfull" << endl;
    } else {
        cout << "ERROR: correct proof failed to validate" << endl;
    }
    for (int i = 0; i < n; i++) {
        EC_POINT_free(g[i]);
        EC_POINT_free(y[i]);
    }
    free(g);
    free(y);
    BN_free(x);
    return res;
}

int main() {
    CorrectProof();
}
