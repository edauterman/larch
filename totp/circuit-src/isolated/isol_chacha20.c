#include <stdint.h>
#include <stdio.h>

#include "chacha20.c"

#include "circuit_params.h"

#define DIGITS 6
#define PERIOD 30

#define BLOCK_SIZE 64
#define OUT_SIZE 20
#define KEY_LEN BLOCK_SIZE
#define MSG_LEN 8

struct InputA {
    uint8_t key[32];
    uint8_t nonce[12];
};

struct InputB {
    uint8_t msg[2];
};

struct Output {
    uint8_t encb[2];
};

struct Output mpc_main() {
    struct InputA INPUT_A;
    struct InputB INPUT_B;
    struct Output out;

    uint8_t chacha_block[64];
    chacha20_block(chacha_block, INPUT_A.key, 0, INPUT_A.nonce);

    out.encb[0] = chacha_block[0] ^ INPUT_B.msg[0];
    out.encb[1] = chacha_block[1] ^ INPUT_B.msg[1];

    return out;
}
