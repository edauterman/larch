#include <stdint.h>
#include <stdio.h>

#include "sha256.c"

#include "circuit_params.h"

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8

struct InputA {
    uint8_t msg[48];
};

struct InputB {
};

struct Output {
    uint8_t hash[32];
};

struct Output mpc_main() {
    struct InputA INPUT_A;
    struct InputB INPUT_B;
    struct Output out;

    // calc_sha_256(commitment, commit_buf, 32 + 16);
    SHA256_CTX ctx;
    memset(ctx.data, 0, 64);
    sha256_init(&ctx);
    sha256_update(&ctx, INPUT_A.msg, 32 + 16);
    sha256_final(&ctx, out.hash);

    return out;
}
