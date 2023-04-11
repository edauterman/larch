#include "emp-tool/emp-tool.h"
#include "../../../larch-host/zkboo/src/circuit_utils.cc"

#include <inttypes.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <vector>
#include <string>
#include <stdio.h>

#define SERVER ALICE
#define CLIENT BOB

#define GRPC_PORT 44444
#define MPC_PORT  44445

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 32 // TODO sha1
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8
#define COMMIT_NONCE_LEN 16
#define COMMIT_LEN 32
#define AUTH_NONCE_LEN 16
#define ENC_RPID_LEN 16
#define SIG_LEN 64

// #ifndef MAX_KEYS
#define MAX_KEYS 64
// #endif

using namespace emp;

void evaluate() {
    // client
    Integer in_client_rp_index(16, 0, ALICE);
    Integer in_client_key_share(KEY_LEN * 8, 0, ALICE);
    Integer in_client_rpid_key(32 * 8, 0, ALICE);
    Integer in_client_rpid_commit_nonce(COMMIT_NONCE_LEN * 8, 0, ALICE);
    Integer in_client_rpid_auth_nonce(AUTH_NONCE_LEN * 8, 0, ALICE);

    // server
    Integer in_server_rpid_key_commitment(COMMIT_LEN * 8, 0, BOB);
    auto in_server_key_shares = new Integer[MAX_KEYS];
    for (int i = 0; i < MAX_KEYS; i++) {
        in_server_key_shares[i] = Integer(KEY_LEN * 8, 0, BOB);
    }
    Integer in_server_time_counter(MSG_LEN * 8, 0, BOB);

    // output
    Integer out_hmac(OUT_SIZE * 8, 0, PUBLIC);
    Integer out_enc_rpid(ENC_RPID_LEN * 8, 0, PUBLIC);

    // start
    // prep mask
    Integer server_key_share_mask(KEY_LEN * 8, 0, PUBLIC);
    // fill with ones
    auto _sk_mask_bits = new bool[KEY_LEN * 8];
    memset(_sk_mask_bits, 1, KEY_LEN * 8);
    server_key_share_mask.init(_sk_mask_bits, KEY_LEN * 8, PUBLIC);
    // resize and shift by key index
    Integer _sk_mask_mul(MAX_KEYS * KEY_LEN * 8, KEY_LEN * 8, PUBLIC);
    server_key_share_mask = server_key_share_mask.resize(MAX_KEYS * KEY_LEN * 8) >> (in_client_rp_index * _sk_mask_mul);
    for (int i = 0; i < MAX_KEYS; i++) {
        server_key_share_mask = server_key_share_mask ^ in_server_key_shares[i];
    }
    // server_key_share
    Integer server_key_share(KEY_LEN * 8, 0, PUBLIC);
    for (int i = 0; i < MAX_KEYS; i++) {
        Integer tmp = server_key_share_mask
        server_key_share = server_key_share ^ (in_server_key_shares[i] & (server_key_share_mask.resize());
    }
    Integer mac_key = server_key_share ^ in_client_key_share;

    // HMAC
    // TODO sha1
    hmac(
        (block*) mac_key.bits.data(),
        KEY_LEN * 8,
        (block*) in_server_time_counter.bits.data(),
        MSG_LEN * 8,
        (block*) out_hmac.bits.data()
    );

    // AES
    AES_128_CTR_Calculator aes;
    Integer enc_rpid_buf(ENC_RPID_LEN * 8, 0, PUBLIC);
    enc_rpid_buf = enc_rpid_buf | in_client_rpid_auth_nonce; // TODO wrong
    aes.aes_128_ctr(
        *(block*) in_client_rpid_key.bits.data(),
        *(block*) in_client_rpid_auth_nonce.bits.data(),
        (block*) enc_rpid_buf.bits.data(),
        (block*) out_enc_rpid.bits.data()
    );

    // commitment
    Integer commit_buf((32 + COMMIT_NONCE_LEN) * 8, 0, PUBLIC);
    commit_buf = (commit_buf | in_client_rpid_commit_nonce.resize((32 + COMMIT_NONCE_LEN) * 8)) >> (32 * 8);
    commit_buf = commit_buf | in_client_rpid_key.resize((32 + COMMIT_NONCE_LEN) * 8);
    Integer commitment(COMMIT_LEN * 8, 0, PUBLIC);
    sha256((block*) commit_buf.bits.data(), (block*) commitment.bits.data(), COMMIT_NONCE_LEN * 8, CircuitExecution::circ_exec);

    // check commitment
    Integer _xor_mask(COMMIT_LEN * 8, 0, PUBLIC);
    auto _mask_bits = new bool[COMMIT_LEN * 8];
    memset(_mask_bits, 1, COMMIT_LEN * 8);
    _xor_mask.init(_mask_bits, COMMIT_LEN * 8, PUBLIC);
    auto commitment_mask = commitment ^ in_server_rpid_key_commitment;
    commitment_mask = commitment_mask ^ _xor_mask;
    out_hmac = out_hmac & commitment_mask;

    out_hmac.reveal<string>();
    out_enc_rpid.reveal<string>();
}

int main(int argc, char** argv) {
    string circ_name("totp" + to_string(MAX_KEYS));
    auto filename = circ_name + ".txt";

	setup_plain_prot(true, filename);
    evaluate();
	finalize_plain_prot ();

    // preparsed
	BristolFormat bf(filename.c_str());
    auto h_name = circ_name + ".h";
	bf.to_file(h_name.c_str(), circ_name.c_str());
    return 0;
}
