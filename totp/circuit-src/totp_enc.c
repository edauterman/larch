#include <stdint.h>
#include <stdio.h>

// #include "sha1/sha1.c"
#include "chacha20.c"
#include "sha1_oryx.c"
// #include "sha-2/sha-256.c"
#include "sha256.c"
// #include "tiny-AES-c/aes.c"

#include "circuit_params.h"

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8

// void SHA1(char *hash_out, const char *str, int len)

void SHA1_i0(uint8_t *hash_out, const uint8_t *str, int len)
{
    uint8_t digest_buf[20];
    uint8_t buffer_buf[64];

    Sha1Context ctx = {
        .h = (uint32_t *)digest_buf,
        .digest = digest_buf,
        .w = (uint32_t *)buffer_buf,
        .buffer = buffer_buf,
        .size = 0,
        .totalSize = 0
    };
    sha1Init(&ctx);
    sha1Update_i0(&ctx, (uint8_t *)str, len);
    sha1Final(&ctx, hash_out);
}

void SHA1_i1(uint8_t *hash_out, const uint8_t *str, int len)
{
    uint8_t digest_buf[20];
    uint8_t buffer_buf[64];

    Sha1Context ctx = {
        .h = (uint32_t *)digest_buf,
        .digest = digest_buf,
        .w = (uint32_t *)buffer_buf,
        .buffer = buffer_buf,
        .size = 0,
        .totalSize = 0
    };
    sha1Init(&ctx);
    sha1Update_i1(&ctx, (uint8_t *)str, len);
    sha1Final(&ctx, hash_out);
}

static void hmac_sha1(uint8_t* key, uint8_t* msg, uint8_t* out_mac) {
    // keys must be pre-processed as we can't handle variable-len inputs
    uint8_t ipad_buf[BLOCK_SIZE + MSG_LEN] = { 0, };
    uint8_t opad_buf[BLOCK_SIZE + OUT_SIZE] = { 0, };
    uint8_t tmp[OUT_SIZE] = { 0, };

    for (int i = 0; i < KEY_LEN; i++) {
        ipad_buf[i] = key[i] ^ 0x36;
        opad_buf[i] = key[i] ^ 0x5c;
    }

    memcpy(ipad_buf + KEY_LEN, msg, 8);
    SHA1_i0(opad_buf + KEY_LEN, ipad_buf, KEY_LEN + MSG_LEN);
    SHA1_i1(out_mac, opad_buf, KEY_LEN + OUT_SIZE);
}

struct InputA {
    uint16_t rp_index;
    uint8_t client_key_share[KEY_LEN];

    uint8_t client_rpid_key[32];
    uint8_t client_rpid_commit_nonce[16];
    uint8_t client_rpid_auth_nonce[12];
};

struct InputB {
    uint8_t server_rpid_key_commitment[32];
    uint8_t server_key_shares[KEY_LEN * MAX_KEYS];
    uint8_t server_time_counter[MSG_LEN];
    uint8_t server_rpid_auth_nonce[12];
};

struct Output {
    //uint32_t otp;
    //uint8_t enc_rpid;
    // compiler workaround
    uint8_t data[4 + 2];
};

struct Output mpc_main() {
    struct InputA INPUT_A;
    struct InputB INPUT_B;
    struct Output out;

    unsigned int commit_ok = memcmp(INPUT_A.client_rpid_auth_nonce, INPUT_B.server_rpid_auth_nonce, 12);

    // Generate and check commitment to verify rpid key
    uint8_t commitment[32];
    uint8_t commit_buf[32 + 16] = { 0, };
    memcpy(commit_buf, INPUT_A.client_rpid_key, 32);
    memcpy(commit_buf + 32, INPUT_A.client_rpid_commit_nonce, 16);
    // calc_sha_256(commitment, commit_buf, 32 + 16);
    SHA256_CTX ctx;
    memset(ctx.data, 0, 64);
    sha256_init(&ctx);
    sha256_update(&ctx, commit_buf, 32 + 16);
    sha256_final(&ctx, commitment);
    commit_ok = commit_ok & (memcmp(commitment, INPUT_B.server_rpid_key_commitment, 32) == 0);

    // decrypt otp key from keybag
    uint8_t otp_key[KEY_LEN];
    for (int i = 0; i < KEY_LEN; i++) {
        otp_key[i] = INPUT_A.client_key_share[i] ^ INPUT_B.server_key_shares[INPUT_A.rp_index * KEY_LEN + i];
    }

    // generate otp
    uint8_t otp_mac[OUT_SIZE] = { 0, };
    hmac_sha1(otp_key, INPUT_B.server_time_counter, otp_mac);

    unsigned int offset = otp_mac[19] & 0xf;
    unsigned int P = (otp_mac[offset] & 0x7f) << 24 |
            otp_mac[offset + 1] << 16 |
            otp_mac[offset + 2] << 8 |
            otp_mac[offset + 3];

    // encrypt rpid
    uint8_t chacha_block[64];
    chacha20_block(chacha_block, INPUT_A.client_rpid_key, 0, INPUT_A.client_rpid_auth_nonce);
    out.data[4] = chacha_block[0] ^ ((INPUT_A.rp_index >> 8) & 0xff);
    out.data[5] = chacha_block[1] ^ (INPUT_A.rp_index & 0xff);

    unsigned int otp = (P % 1000000) * commit_ok;

    out.data[0] = (otp & 0xff000000) >> 24;
    out.data[1] = (otp & 0x00ff0000) >> 16;
    out.data[2] = (otp & 0x0000ff00) >> 8;
    out.data[3] = (otp & 0x000000ff);
    out.data[4] = chacha_block[0] ^ ((INPUT_A.rp_index >> 8) & 0xff);
    out.data[5] = chacha_block[1] ^ (INPUT_A.rp_index & 0xff);
    return out;
}
