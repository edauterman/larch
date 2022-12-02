#ifndef _PW_H_
#define _PW_H_

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "params.h"
#include "or_groth.h"

class ElGamalCt {
    EC_POINT *R;
    EC_POINT *C;
};

class PasswordClient {
    EC_POINT *StartEnroll();
    void FinishEnroll(EC_POINT *recover_pt_in);
    EC_POINT *StartRegister(uint8_t *id, int len);
    void FinishRegister(EC_POINT *in, EC_POINT *pw);
    void StartAuth(uint8_t *id, int len, ElGamalCt *ct, OrProof *or_proof, DDHProof *ddh_proof, BIGNUM *r);
    void FinishAuth(int register_idx, EC_POINT *out, EC_POINT *in, BIGNUM *r);

    private:
        Params params;
        BIGNUM *x;
        EC_POINT *X;
        EC_POINT *recover_pt;
        vector<EC_POINT *>bases_inv;
        vector<EC_POINT *>client_shares;
};

class PasswordLog {
    EC_POINT *Enroll(EC_POINT *X_in);
    void Register(EC_POINT *base);
    void Auth(EC_POINT *out, ElGamalCt *ct, OrProof *or_proof, DDHProof *ddh_proof);

    private:
        Params params;
        BIGNUM *sk;
        EC_POINT *X;
        vector<EC_POINT *>bases_inv;
        vector<ElGamalCt *>cts;
};


#endif
