#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <emp-tool/emp-tool.h>

#include "../agent/params.h"

class LogServer {
    public:
        LogServer();
        void GenerateKeyPair(uint8_t *x_out, uint8_t *y_out);
        void VerifyProofAndSign(uint8_t *proof_bytes, uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *sig_out, unsigned int *sig_len);

    private:
        const int numRands = 104116;
        const int m_len = 256;
        const int challenge_len = 552;
        EVP_PKEY *pkey;
        EC_KEY *key;
        Params params;
        int port;


};

#endif
