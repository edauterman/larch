#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
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
    OrProof *or_proof_r;
    OrProof *or_proof_x;
    RAND_bytes(id, len);
   
    EC_POINT *X = EC_POINT_new(Params_group(params)); 
    EC_POINT *sig_pk = EC_POINT_new(Params_group(params)); 
    c.StartEnroll(X, sig_pk);
    EC_POINT *recover_pt = l.Enroll(X,sig_pk);
    c.FinishEnroll(recover_pt);

    c.StartRegister(id, len);
    EC_POINT *out = l.Register(id, len);
    c.FinishRegister(out, pw);

    uint8_t *sig;
    unsigned int sig_len;
    c.StartAuth(0, id, len, ct, &or_proof_x, &or_proof_r, r, &sig, &sig_len);
    EC_POINT *out2 = l.Auth(ct, or_proof_x, or_proof_r, sig);
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
