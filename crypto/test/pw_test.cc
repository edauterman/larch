#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <vector>

#include "../src/or_groth.h"
#include "../src/pw.h"

using namespace std;

bool CorrectAuth() {
    PasswordClient c;
    PasswordLog l;
    uint8_t id[16];
    int len = 16;
    Params params = Params_new(P256);
    EC_POINT *pw = EC_POINT_new(Params_group(params));
    Params_rand_point(params, pw);
    ElGamalCt *ct = new ElGamalCt(params);
    BIGNUM *r = BN_new();
    
    EC_POINT *X = c.StartEnroll();
    EC_POINT *recover_pt = l.Enroll(X);
    c.FinishEnroll(recover_pt);

    EC_POINT *base_inv = c.StartRegister(id, len);
    EC_POINT *out = l.Register(id, len, base_inv);
    c.FinishRegister(out, pw);

    c.StartAuth(id, len, ct, NULL, NULL, r);
    EC_POINT *out2 = l.Auth(ct, NULL, NULL);
    EC_POINT *ret_pw = c.FinishAuth(0, out2, r);

    int res = EC_POINT_cmp(Params_group(params), pw, ret_pw, Params_ctx(params));
    if (res == 0) {
        cout << "Test passed." << endl;
    } else {
        cout << "ERROR: returned incorrect password" << endl;
    }

    return res;
}

int main() {
    CorrectAuth();
}
