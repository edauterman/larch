#ifndef _PW_H_
#define _PW_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <vector>

#include "params.h"
#include "or_groth.h"
#include "ddh_proof.h"

using namespace std;

class ElGamalCt {
    public:
        ElGamalCt(Params params);
        EC_POINT *R;
        EC_POINT *C;
};

class PasswordClient {
    public:
        PasswordClient();
        EC_POINT *StartEnroll();
        void FinishEnroll(EC_POINT *recover_pt_in);
        EC_POINT *StartRegister(uint8_t *id, int len);
        void FinishRegister(EC_POINT *in, EC_POINT *pw);
        void StartAuth(uint8_t *id, int len, ElGamalCt *ct, OrProof *or_proof_x, OrProof *or_proof_r, BIGNUM *r);
        EC_POINT *FinishAuth(int register_idx, EC_POINT *in, BIGNUM *r);

    private:
        Params params;
        BIGNUM *x;
        EC_POINT *X;
        EC_POINT *recover_pt;
        vector<EC_POINT *>bases_inv;
        vector<EC_POINT *>client_shares;
};

class PasswordLog {
    public:
        PasswordLog();
        EC_POINT *Enroll(EC_POINT *X_in);
        EC_POINT *Register(uint8_t *id, int len, EC_POINT *base);
        EC_POINT *Auth(ElGamalCt *ct, OrProof *or_proof_x, OrProof *or_proof_r);

    private:
        Params params;
        BIGNUM *sk;
        EC_POINT *X;
        vector<EC_POINT *>bases_inv;
        vector<ElGamalCt *>cts;
};


#endif
