#include <inttypes.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
#include <vector>
#include <string>
#include <stdio.h>
#include "../../crypto/src/params.h"
#include "../../crypto/src/sigs.h"

#define SERVER ALICE
#define CLIENT BOB

#define PREPARSED_CIRCUIT

#ifndef MAX_KEYS
#define MAX_KEYS 64
#endif

#ifndef BASE_PORT
#define BASE_PORT (44400 + MAX_KEYS)
#endif

#define GRPC_PORT (BASE_PORT + 0)
#define MPC_PORT  (BASE_PORT + 1)

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8
#define COMMIT_NONCE_LEN 16
#define COMMIT_LEN 32
#define AUTH_NONCE_LEN 12
#define ENC_RPID_LEN 2
#define SIG_LEN 64

using namespace emp;

struct InputA {
    uint16_t rp_index;
    char client_key_share[KEY_LEN];

    char client_rpid_key[32];
    char client_rpid_commit_nonce[COMMIT_NONCE_LEN]; // match MSG_LEN to reuse HMAC path
    char client_rpid_auth_nonce[AUTH_NONCE_LEN];
} __attribute__((packed));

struct InputB {
    char server_rpid_key_commitment[COMMIT_LEN];
    char server_key_shares[KEY_LEN * MAX_KEYS];
    char server_time_counter[MSG_LEN];
    char server_rpid_auth_nonce[AUTH_NONCE_LEN];
} __attribute__((packed));

struct Output {
    uint32_t otp;
    uint8_t enc_rpid[ENC_RPID_LEN];
} __attribute__((packed));

struct ClientState {
    uint8_t client_key_shares[KEY_LEN * MAX_KEYS];
    uint8_t rpid_key[32];
    uint8_t rpid_commit_nonce[COMMIT_NONCE_LEN];

    uint8_t rpid_sign_sk[32];
    uint32_t auth_ctr;
} __attribute__((packed));

struct ServerState {
    uint8_t rpid_key_commitment[COMMIT_LEN];
    uint8_t server_key_shares[KEY_LEN * MAX_KEYS];

    uint8_t rpid_sign_pk[65];
} __attribute__((packed));

struct SerializedLogEntry {
    uint64_t timestamp;
    uint8_t enc_rpid[ENC_RPID_LEN];
    uint8_t rpid_sig[SIG_LEN];
} __attribute__((packed));


C2PC<NetIO> *do_mpc_offline(int party, NetIO *io);
Output do_mpc_server(InputB& in_b, C2PC<NetIO> *twopc);
Output do_mpc_client(InputA& in_a, C2PC<NetIO> *twopc);


static BIGNUM* gen_ecdsa(Params params) {
    BIGNUM *sk = BN_new();
    Params_rand_exponent(params, sk);
    return sk;
}

static BIGNUM* load_ecdsa_sk(std::vector<uint8_t>& sk) {
    BIGNUM *bn = BN_new();
    BN_bin2bn(sk.data(), sk.size(), bn);
    return bn;
}

static std::vector<uint8_t> save_ecdsa_sk(BIGNUM* key) {
    std::vector<uint8_t> out(32);
    BN_bn2bin(key, out.data());
    return out;
}

static EC_POINT* load_ecdsa_pk(Params params, std::vector<uint8_t>& pk) {
    EC_POINT *point = EC_POINT_new(Params_group(params));
    EC_POINT_oct2point(Params_group(params), point, pk.data(), pk.size(), NULL);
    return point;
}

static std::vector<uint8_t> save_ecdsa_pk(Params params, EC_POINT* key) {
    std::vector<uint8_t> out(65);
    EC_POINT_point2oct(Params_group(params), key, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), NULL);
    return out;
}

static std::vector<uint8_t> derive_ecdsa_pub(Params params, BIGNUM* key) {
    std::vector<uint8_t> out(65);
    EC_POINT *pk = EC_POINT_new(Params_group(params));
    Params_exp(params, pk, key);
    EC_POINT_point2oct(Params_group(params), pk, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), NULL);
    EC_POINT_free(pk);
    return out;
}

static std::vector<uint8_t> sign_ecdsa(Params params, BIGNUM* sk, std::vector<uint8_t> msg) {
    std::vector<uint8_t> sig(64);
    unsigned int sig_len;
    uint8_t *tmp_sig;
    Sign(msg.data(), msg.size(), sk, &tmp_sig, &sig_len, params);
    memcpy(sig.data(), tmp_sig, sig_len);
    free(tmp_sig);
    sig.resize(sig_len);
    return sig;
}

static bool verify_ecdsa(Params params, EC_POINT* pk, std::vector<uint8_t> msg, std::vector<uint8_t> sig) {
	bool res = VerifySignature(pk, msg.data(), msg.size(), sig.data(), params);
	return res == 0;
}

static void print_hex(const char* label, const char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (uint8_t) data[i]);
    }
    printf("\n");
}

static void print_bits(const char* label, const bool* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%d", data[i]);
    }
    printf("\n");
}
