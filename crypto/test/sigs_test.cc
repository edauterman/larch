#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "../src/sigs.h"

using namespace std;

bool TestCorrectSig() {
    Params params = Params_new(P256);
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(Params_group(params));
    Params_rand_point_exp(params, pk, sk);
    uint8_t buf[32];
    uint8_t *sig;
    unsigned int sig_len;
    Sign(buf, 32, sk, &sig, &sig_len, params);
    int res = VerifySignature(pk, buf, 32, sig, params);
    printf("clientPk = %s\n", EC_POINT_point2hex(Params_group(params), pk, POINT_CONVERSION_UNCOMPRESSED, Params_ctx(params)));
    if (res == 0) {
        cout << "Test passed" << endl;
    } else {
        cout << "ERROR: Correct signature does not verify" << endl;
    }
    return res;
}

bool TestBadSig() {
    Params params = Params_new(P256);
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(Params_group(params));
    Params_rand_point_exp(params, pk, sk);
    uint8_t buf[32];
    uint8_t *sig;
    unsigned int sig_len;
    Sign(buf, 32, sk, &sig, &sig_len, params);
    sig[12] = !sig[12];
    int res = VerifySignature(pk, buf, 32, sig, params);
    if (res == 0) {
        cout << "ERROR: Corrupt signature verified" << endl;
    } else {
        cout << "Test passed" << endl;
    }
    return res;
}

bool TestBadKey() {
    Params params = Params_new(P256);
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(Params_group(params));
    BIGNUM *skbad = BN_new();
    EC_POINT *pkbad = EC_POINT_new(Params_group(params));
    Params_rand_point_exp(params, pk, sk);
    Params_rand_point_exp(params, pkbad, skbad);
    uint8_t buf[32];
    uint8_t *sig;
    unsigned int sig_len;
    Sign(buf, 32, skbad, &sig, &sig_len, params);
    int res = VerifySignature(pk, buf, 32, sig, params);
    if (res == 0) {
        cout << "ERROR: Signature verified with wrong key" << endl;
    } else {
        cout << "Test passed" << endl;
    }
    return res;
}

int main() {

    Params params = Params_new(P256);
    EC_POINT *pk = EC_POINT_new(Params_group(params));
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (Params_rand_point(params, pk) != 1) printf("BAD\n");
    printf("randPk = %s\n", EC_POINT_point2hex(Params_group(params), pk, POINT_CONVERSION_UNCOMPRESSED, Params_ctx(params)));
    EC_POINT_get_affine_coordinates_GFp(Params_group(params), pk, x, y, Params_ctx(params));
    printf("x = %s\n", BN_bn2hex(x));
    printf("y = %s\n", BN_bn2hex(y));


    TestCorrectSig();
    TestBadSig();
    TestBadKey();
}
