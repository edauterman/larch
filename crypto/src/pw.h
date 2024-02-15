#ifndef _PW_H_
#define _PW_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <vector>

#include "params.h"
#include "or_groth.h"

using namespace std;

class ElGamalCt {
    public:
        ElGamalCt(Params params);
        EC_POINT *R;
        EC_POINT *C;
};

class PasswordClient {
    public:
        Params params;
        Params params2;
        PasswordClient();
        void StartEnroll(EC_POINT *X_out, EC_POINT *sig_pk_out);
        void FinishEnroll(EC_POINT *recover_pt_in);
        void StartRegister(const uint8_t *id, int len);
        void FinishRegister(EC_POINT *in, EC_POINT *pw);
        void StartAuth(int register_idx, const uint8_t *id, int len, ElGamalCt *ct, OrProof **or_proof_x, OrProof **or_proof_r, BIGNUM *r);
        EC_POINT *FinishAuth(int register_idx, EC_POINT *in, BIGNUM *r);
        void PrintLogEntry(ElGamalCt *ct, uint8_t *sig, uint64_t time);

    private:
        BIGNUM *x;
        EC_POINT *X;
        EC_POINT *recover_pt;
        vector<EC_POINT *>bases_inv;
        vector<EC_POINT *>hash_ids;
        vector<EC_POINT *>client_shares;
};

class PasswordLog {
    public:
        Params params;
        Params params2;
        PasswordLog();
        EC_POINT *Enroll(EC_POINT *X_in, EC_POINT *pk_in);
        EC_POINT *Register(const uint8_t *id, int len);
        EC_POINT *Auth(ElGamalCt *ct, OrProof *or_proof_x, OrProof *or_proof_r, uint8_t *sig);

    private:
        BIGNUM *sk;
        EC_POINT *X;
        EC_POINT *pk;
        vector<EC_POINT *>bases_inv;
        vector<ElGamalCt *>cts;
};


#endif
