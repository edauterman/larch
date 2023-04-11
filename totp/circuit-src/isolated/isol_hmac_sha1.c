#include <stdint.h>
#include <stdio.h>

#include "sha1_oryx.c"

#include "circuit_params.h"

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8

// void SHA1(char *hash_out, const char *str, int len)

void SHA1_i0(char *hash_out, const char *str, int len)
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

void SHA1_i1(char *hash_out, const char *str, int len)
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

static void hmac_sha1(char* key, char* msg, char* out_mac) {
    // keys must be pre-processed as we can't handle variable-len inputs
    char ipad_buf[BLOCK_SIZE + MSG_LEN] = { 0, };
    char opad_buf[BLOCK_SIZE + OUT_SIZE] = { 0, };
    char tmp[OUT_SIZE] = { 0, };

    for (int i = 0; i < KEY_LEN; i++) {
        ipad_buf[i] = key[i] ^ 0x36;
        opad_buf[i] = key[i] ^ 0x5c;
    }

    memcpy(ipad_buf + KEY_LEN, msg, 8);
    SHA1_i0(opad_buf + KEY_LEN, ipad_buf, KEY_LEN + MSG_LEN);
    SHA1_i1(out_mac, opad_buf, KEY_LEN + OUT_SIZE);
}

struct InputA {
    uint8_t key[KEY_LEN];
};

struct InputB {
    uint8_t msg[MSG_LEN];
};

struct Output {
    uint8_t mac[20];
};

struct Output mpc_main() {
    struct InputA INPUT_A;
    struct InputB INPUT_B;
    struct Output out;

    hmac_sha1(INPUT_A.key, INPUT_B.msg, out.mac);
    return out;
}
