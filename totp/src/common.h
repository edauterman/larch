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
#include "params.h"
#include "sigs.h"

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
} __attribute__((packed));

struct Output {
    uint32_t otp;
    uint8_t enc_rpid[ENC_RPID_LEN];
    // unsigned char data[5];
} __attribute__((packed));

struct ClientState {
    uint8_t client_key_shares[KEY_LEN * MAX_KEYS];
    uint8_t rpid_key[32];
    uint8_t rpid_commit_nonce[COMMIT_NONCE_LEN];

    uint8_t rpid_sign_sk[32];
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


static EC_KEY* gen_ecdsa() {
    EC_KEY* key = EC_KEY_new_by_curve_name(415);
    //EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);
    return key;
}

static EC_KEY* load_ecdsa_sk(std::vector<uint8_t>& sk) {
    EC_KEY* key = EC_KEY_new_by_curve_name(415);
    //EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *bn = BN_new();
    BN_bin2bn(sk.data(), sk.size(), bn);
    EC_KEY_set_private_key(key, BN_bin2bn(sk.data(), sk.size(), NULL));
    return key;
}

static std::vector<uint8_t> save_ecdsa_sk(EC_KEY* key) {
    std::vector<uint8_t> out(32);
    BN_bn2bin(EC_KEY_get0_private_key(key), out.data());
    return out;
}

static EC_KEY* load_ecdsa_pk(std::vector<uint8_t>& pk) {
    EC_KEY* key = EC_KEY_new_by_curve_name(415);
    //EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(key));
    EC_POINT_oct2point(EC_KEY_get0_group(key), point, pk.data(), pk.size(), NULL);
    EC_KEY_set_public_key(key, point);
    return key;
}

static std::vector<uint8_t> save_ecdsa_pk(EC_KEY* key) {
    std::vector<uint8_t> out(65);
    EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), NULL);
    return out;
}

static std::vector<uint8_t> derive_ecdsa_pub(EC_KEY* key) {
    std::vector<uint8_t> out(65);
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), NULL);
    return out;
}

static std::vector<uint8_t> sign_ecdsa(EC_KEY* sk, std::vector<uint8_t> msg) {
    std::vector<uint8_t> sig(64);
    unsigned int sig_len;
    uint8_t *tmp_sig;
    Params params = Params_new(P256);
    ECDSASign(msg.data(), msg.size(), EC_KEY_get0_private_key(sk), &tmp_sig, &sig_len, params);
    memcpy(sig.data(), tmp_sig, sig_len);
    free(tmp_sig);
    Params_free(params);
    sig.resize(sig_len);
    return sig;
}

static bool verify_ecdsa(EC_KEY* pk, std::vector<uint8_t> msg, std::vector<uint8_t> sig) {
   	Params params = Params_new(P256);
	bool res = ECDSAVerify(EC_KEY_get0_public_key(pk), msg.data(), msg.size(), sig.data(), params);
	Params_free(params);
	return res;
	//return 1;//ECDSA_verify(0, msg.data(), msg.size(), sig.data(), sig.size(), pk) == 1;
}

/*
static std::vector<uint8_t> sign_ecdsa(EC_KEY* sk, std::vector<uint8_t> msg) {
    std::vector<uint8_t> sig(128);
    unsigned int sig_len;
    ECDSA_sign(0, msg.data(), msg.size(), sig.data(), &sig_len, sk);
    sig.resize(sig_len);
    return sig;
}

static bool verify_ecdsa(EC_KEY* pk, std::vector<uint8_t> msg, std::vector<uint8_t> sig) {
    return ECDSA_verify(0, msg.data(), msg.size(), sig.data(), sig.size(), pk) == 1;
}*/

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
