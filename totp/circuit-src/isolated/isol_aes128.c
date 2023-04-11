#include <stdint.h>
#include <stdio.h>

#include "tiny-AES-c/aes.c"

#include "circuit_params.h"

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8

struct InputA {
    uint8_t key[32];
    uint8_t iv[16];
};

struct InputB {
    uint8_t msg[16];
};

struct Output {
    uint8_t encb[16];
};

struct Output mpc_main() {
    struct InputA INPUT_A;
    struct InputB INPUT_B;
    struct Output out;

    // encrypt rpid
    uint8_t aes_block[16];
    memcpy(aes_block, INPUT_B.msg, 16);
    // AES-256-CBC
    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, INPUT_A.key, INPUT_A.iv);
    AES_CBC_encrypt_buffer(&aes_ctx, aes_block, 16);
    memcpy(out.encb, aes_block, 16);

    return out;
}
