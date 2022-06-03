#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <emp-tool/emp-tool.h>

#include "../crypto/params.h"
#include "../agent/u2f.h"

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
        BIGNUM *check_e;
        BIGNUM *out;

        AuthState(BIGNUM *check_d, BIGNUM *check_e, BIGNUM *out);
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
        void VerifyProofAndSign(uint32_t id, uint8_t *proof_bytes[NUM_ROUNDS], uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *auth_sig, unsigned int auth_sig_len, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len, uint32_t *sessionCtr);
        void FinishSign(uint32_t sessionCtr, uint8_t *check_d_buf, unsigned int check_d_len, uint8_t *check_e_buf, unsigned int check_e_len, uint8_t *out, unsigned int *out_len);
        void GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret);
        void GetPreprocessValue(uint64_t ctr, BIGNUM *ret, uint8_t *seed_in);
        void GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *alpha, uint8_t *seed_in);

    private:
        const int numRands = 104116;
        const int m_len = 256;
        const int challenge_len = 552;

        bool onlySigs;

        /*BIGNUM *sk;
        EC_POINT *pk;
        vector<Hint> hints;
        map<uint32_t, AuthState *> saveMap;
        uint8_t enc_key_comm[32];
        uint32_t auth_ctr;*/
        map<uint32_t, InitState *>clientMap;
        map<uint32_t, AuthState *> saveMap;
        map<uint32_t, Token *> tokenMap;

        EVP_PKEY *pkey;
        EC_KEY *key;
        Params params;
        int port;


};

#endif
