#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <emp-tool/emp-tool.h>

#include "../crypto/params.h"

class LogServer {
    public:
        LogServer();
        void Initialize(const InitRequest *req, uint8_t *pkBuf);
        void GenerateKeyPair(uint8_t *x_out, uint8_t *y_out);
        void VerifyProofAndSign(uint8_t *proof_bytes, uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *sig_out, unsigned int *sig_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len);

    private:
        const int numRands = 104116;
        const int m_len = 256;
        const int challenge_len = 552;

        BIGNUM *sk;
        EC_POINT *pk;
        vector<Hint> hints;
        uint8_t enc_key_comm[32];
        uint32_t auth_ctr;

        EVP_PKEY *pkey;
        EC_KEY *key;
        Params params;
        int port;


};

#endif
