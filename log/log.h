#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <emp-tool/emp-tool.h>

#include "../crypto/params.h"
#include "../client/src/u2f.h"

#define NUM_ROUNDS 5

class Token {
    public:
        uint8_t ct[SHA256_DIGEST_LENGTH];
        uint8_t iv[16];
        uint8_t sig[MAX_ECDSA_SIG_SIZE];

        Token(uint8_t *ct, uint8_t *iv, uint8_t *sig, unsigned int sig_len);
};

class AuthState {
    public:
        BIGNUM *check_d;
        uint8_t r[16];
        uint8_t other_cm_check_d[32];
        BIGNUM *out;

        AuthState(BIGNUM *check_d, uint8_t *r, BIGNUM *out);
};

class InitState {
    public:
        BIGNUM *sk;
        EC_POINT *pk;
        vector<Hint> hints;
        uint8_t enc_key_comm[32];
        uint32_t auth_ctr;
        EC_POINT *auth_pk;
        uint8_t log_seed[16];

        InitState();
};

class LogServer {
    public:
        LogServer(bool onlySigs);
        void Initialize(const InitRequest *req, uint8_t *pkBuf);
        void GenerateKeyPair(uint8_t *x_out, uint8_t *y_out);
        void VerifyProofAndSign(uint32_t id, uint8_t *proof_bytes[NUM_ROUNDS], uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *auth_sig, unsigned int auth_sig_len, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len, uint8_t *cm_check_d, uint32_t *sessionCtr);
        void FinishSign(uint32_t sessionCtr, uint8_t *cm_check_d, uint8_t *check_d_buf_out, unsigned int *check_d_buf_len, uint8_t *check_d_open);
       void FinalSign(uint32_t sessionCtr, uint8_t *check_d_buf, unsigned int check_d_len, uint8_t *check_d_open, uint8_t *final_out, unsigned int *final_out_len); 
        void GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *alpha, uint8_t *seed_in);

    private:
        const int numRands = 104116;
        const int m_len = 256;
        const int challenge_len = 552;

        bool onlySigs;

        map<uint32_t, InitState *>clientMap;
        map<uint32_t, AuthState *> saveMap;
        map<uint32_t, Token *> tokenMap;

        EVP_PKEY *pkey;
        EC_KEY *key;
        Params params;
        int port;
};

#endif
