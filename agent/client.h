#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <map>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "u2f.h"
#include "../crypto/params.h"
#include "../crypto/sigs.h"

using namespace std;

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
class KeyHandle {
  public:
  uint8_t data[MAX_KH_SIZE];
  KeyHandle(const uint8_t *data);
  bool operator<(const KeyHandle &src) const;
};

class Client {
    public:
        Client();
        void ReadFromStorage();
        void WriteToStorage();

        int Initialize();

        /* Run registration with origin specified by app_id. Outputs the key handle and
        * public key, and generates a self-signed cert and corresponding batch
        * signature (created entirely at the agent). Returns sum of length of
        * attestation certificate and batch signature, or 0 on failure.*/
        int Register(uint8_t *app_id, uint8_t *challenge,
                    uint8_t *key_handle_out, P256_POINT *pk_out, uint8_t *cert_sig_out);

        /* Authenticate at origin specified by app_id given a challenge from the origin
        * and a key handle obtained from registration. Outputs the flags, counter, and
        * sanitized signature from the device. Returns the length of the signature, or
        * 0 on failure. */
        int Authenticate(uint8_t *app_id, int app_id_len, uint8_t *challenge,
                        uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                        uint8_t *sig_out, bool checkOnly = false);
    private:
        Params params;
        map<string, EC_POINT*> pk_map;
        map<string, BIGNUM*> sk_map;
        string logAddr;
        uint8_t seed[16];
        vector<ShortHint> clientHints;
        EC_POINT *logPk;
        uint8_t enc_key[16];
        uint8_t r_open[16];
        uint8_t enc_key_comm[32];
        uint32_t auth_ctr;

        const int NUM_AUTHS = 10;
        //const int NUM_AUTHS = 10000;

        void Preprocess(vector<Hint> &logHints);
        void GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret);
        void GetPreprocessValue(uint64_t ctr, BIGNUM *ret);
        void GetPreprocessValueSet(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c);
        void GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c);

        int StartSigning(BIGNUM *msg_hash, BIGNUM *sk, BIGNUM *x_coord, BIGNUM *val, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, BIGNUM *e);
        int FinishSigning(BIGNUM *val, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *d_client, BIGNUM *d_log, BIGNUM *e_client, BIGNUM *e_log, BIGNUM *out);

};

#endif
