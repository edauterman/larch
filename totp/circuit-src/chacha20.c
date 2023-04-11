#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef unsigned char byte;

static const char *key_quarter_constant = "expand 32-byte k";

static inline uint32_t rotl32(uint32_t a, unsigned int b)
{
	b &= 31;
  	return (a << b) | (a >> (32 - b));
}

static void quarter_round(uint32_t *blk, size_t ai, size_t bi, size_t ci, size_t di) {
    // Unpack into a, b, c, and d variables for easier access
    uint32_t a = blk[ai];
    uint32_t b = blk[bi];
    uint32_t c = blk[ci];
    uint32_t d = blk[di];

    a += b;  d = rotl32(d ^ a, 16);
    c += d;  b = rotl32(b ^ c, 12);
    a += b;  d = rotl32(d ^ a, 8);
    c += d;  b = rotl32(b ^ c, 7);

    // Apply changes to block
    blk[ai] = a;
    blk[bi] = b;
    blk[ci] = c;
    blk[di] = d;
}

static void scramble_block(uint32_t *blk) {
    // 20 rounds per block
    // There are 2 rounds per loop (1 column and 1 diagonal round), so we run this 10 times
    for (int i = 0; i < 10; i++) {
        // Column round (4 quarter rounds => 1 full round)
        quarter_round(blk, 0, 4,  8, 12); // col 0
        quarter_round(blk, 1, 5,  9, 13); // col 1
        quarter_round(blk, 2, 6, 10, 14); // col 2
        quarter_round(blk, 3, 7, 11, 15); // col 3

        // Diagonal round (4 quarter rounds => 1 full round)
        quarter_round(blk, 0, 5, 10, 15);
        quarter_round(blk, 1, 6, 11, 12);
        quarter_round(blk, 2, 7,  8, 13);
        quarter_round(blk, 3, 4,  9, 14);
    }
}

static void process_block(uint32_t *blk) {
    // Save the original block so we can add it later
    uint32_t unscrambled[16];
    // memcpy(unscrambled, blk, sizeof(unscrambled));
    // unroll the memcpy call above.
    unscrambled[0] = blk[0];
    unscrambled[1] = blk[1];
    unscrambled[2] = blk[2];
    unscrambled[3] = blk[3];
    unscrambled[4] = blk[4];
    unscrambled[5] = blk[5];
    unscrambled[6] = blk[6];
    unscrambled[7] = blk[7];
    unscrambled[8] = blk[8];
    unscrambled[9] = blk[9];
    unscrambled[10] = blk[10];
    unscrambled[11] = blk[11];
    unscrambled[12] = blk[12];
    unscrambled[13] = blk[13];
    unscrambled[14] = blk[14];
    unscrambled[15] = blk[15];

    // Scramble the block
    scramble_block(blk);

    // Add the original block to the scrambled one to prevent reversion
    for (int i = 0; i < 16; i++) {
        blk[i] += unscrambled[i];
    }
}

static void fill_block(uint32_t *blk, byte *key, uint32_t counter, char nonce[12]) {
    memcpy(blk, key_quarter_constant, strlen(key_quarter_constant));
    memcpy(blk + 4, key, 32);
    memcpy(blk + 12, &counter, 4);
    memcpy(blk + 13, nonce, 12);
}

void chacha20_block(uint32_t *blk, byte *key, uint32_t counter, char nonce[12]) {
    fill_block(blk, key, counter, nonce);
    process_block(blk);
}

// int main() {
//     byte key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//     uint64_t nonce = 0x0706050403020100;
//     uint64_t counter = 0;

//     while (1) {
//         byte data_block[64];
//         int ret = read(0, data_block, 64);
//         if (ret < 0) {
//             perror("Error reading data");
//             return 1;
//         } else if (ret == 0) {
//             return 0;
//         }

//         byte chacha_block[64];
//         chacha20_block((uint32_t *) chacha_block, key, counter, nonce);

//         for (int i = 0; i < 64; i++) {
//             data_block[i] ^= chacha_block[i];
//         }

//         ret = write(1, data_block, 64);
//         if (ret < 0) {
//             perror("Error writing data");
//             return 1;
//         }

//         counter++;
//     }

//     return 0;
// }
