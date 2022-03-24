#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "proof.h"
#include "prover.h"
#include "common.h"
#include "view.h"

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    if (val == 0) {    
        *x = *x & (val << bit);
    } else {
        *x = *x | (val << bit);
    }   
}

RandomSource::RandomSource(uint8_t *in_seed, int numRands) {
    memcpy(seed, in_seed, 16);
    //RAND_bytes(seed, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    uint8_t iv[16];
    uint8_t pt[16];
    memset(iv, 0, 16);
    memset(pt, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, iv);
    int len;
    randomness = (uint8_t *)malloc(numRands / 8 + 16);
    for (int i = 0; i < numRands / (8 * 16) + 1; i++) {
        EVP_EncryptUpdate(ctx, &randomness[i * 16], &len, pt, 16);
    }   
    EVP_CIPHER_CTX_free(ctx);
}

uint8_t RandomSource::GetRand(int gate) {
    return GetBit(randomness[gate/8], gate%8);
    /*return 1;
    int buf[2 + SHA256_DIGEST_LENGTH / sizeof(int)];
    buf[0] = gate;
    //buf[1] = wireIdx % 3;
    memcpy((uint8_t *)(buf + 1), seed, SHA256_DIGEST_LENGTH);
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), (uint8_t *)buf, sizeof(int) + SHA256_DIGEST_LENGTH);
    return (out) % 2;*/
}

uint8_t RandomOracle::GetRand(CircuitComm *in) {
    uint8_t out;
    hash_to_bytes((uint8_t *)&out, sizeof(uint8_t), in->digest, SHA256_DIGEST_LENGTH);
    return out;
}

void Proof::SerializeInt32(uint32_t x, uint8_t **buf) {
    *buf[0] = x & 0xFF;
    *buf[1] = (x >> 8) & 0xFF;
    *buf[2] = (x >> 16) & 0xFF;
    *buf[3] = (x >> 24) & 0xFF;
    *buf += 4;
}

uint32_t Proof::DeserializeInt32(uint8_t **buf) {
    uint32_t out = *buf[0] | (*buf[1] << 8) | (*buf[2] << 16) | (*buf[3] << 24);
    *buf += 4;
    return out;
}

uint8_t *Proof::Serialize(int *out_len) {
   int bytesOutLen = outLen < 8 ? 1 : outLen / 8; 
   int len = (sizeof(uint32_t) * 4) +                       // wLen and outLen and idx and numWires
       (SHA256_DIGEST_LENGTH * 3) +                         // CircuitComm
       (sizeof(uint32_t) * views[0]->wires.size() * 2) +     // views
       (16 * 2) +                                           // seeds for RandomSource
       (sizeof(uint32_t) * wLen * 2) +                      // shares of witness
       (sizeof(uint32_t) * outLen * 2) +                    // shares of output
       (bytesOutLen);                                       // output raw values
    uint8_t *out = (uint8_t *)malloc(len);
    uint8_t *ptr = out;
    uint32_t numWires = views[0]->wires.size();
    SerializeInt32(wLen, &ptr);
    SerializeInt32(outLen, &ptr);
    SerializeInt32(idx, &ptr);
    SerializeInt32(numWires, &ptr);
    // commitments
    for (int i = 0; i < 3; i++) {
        memcpy(ptr, comms[i].digest, 32);
        ptr += 32;
    }
    // views
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < numWires; j++) {
            SerializeInt32(views[i]->wires[j], &ptr);
        }
    }
    // randomness seeds
    for (int i = 0; i < 2; i++) {
        memcpy(ptr, rands[i]->seed, 16);
        ptr += 16;
    }
    // witness shares
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < wLen; j++) {
            SerializeInt32(w[i][j], &ptr);
        }
    }
    // output shares
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < outLen; j++) {
            SerializeInt32(outShares[i][j], &ptr);
        }
    }
    // output
    memcpy(ptr, out, bytesOutLen);
    ptr += bytesOutLen;

    *out_len = len;
    return out;
}

void Proof::Deserialize(uint8_t *buf, int numRands) {
    uint8_t *ptr = buf;
    wLen = DeserializeInt32(&ptr);
    outLen = DeserializeInt32(&ptr);
    idx = DeserializeInt32(&ptr);
    uint32_t numWires = DeserializeInt32(&ptr);
    int bytesOutLen = outLen < 8 ? 1 : outLen / 8; 
    // commitments
    for (int i = 0; i < 3; i++) {
        memcpy(comms[i].digest, ptr, 32);
        ptr += 32;
    }
    // views
    for (int i = 0; i < 2; i++) {
        views[i] = new CircuitView();
        for (int j = 0; j < numWires; j++) {
            views[i]->wires.push_back(DeserializeInt32(&ptr));
        }
    }
    // randomness seeds
    for (int i = 0; i < 2; i++) {
        rands[i] = new RandomSource(ptr, numRands);
        ptr += 16;
        // TODO expand seed
    }
    // witness shares
    for (int i = 0; i < 2; i++) {
        w[i] = (uint32_t *)malloc(sizeof(uint32_t) * wLen);
        for (int j = 0; j < wLen; j++) {
            w[i][j] = DeserializeInt32(&ptr);
        }
    }
    // output shares
    for (int i = 0; i < 2; i++) {
        outShares[i] = (uint32_t *)malloc(sizeof(uint32_t) * outLen);
        for (int j = 0; j < outLen; j++) {
            outShares[i][j] = DeserializeInt32(&ptr);
        }
    }
    // output
    out = (uint8_t *)malloc(bytesOutLen);
    memcpy(out, ptr, bytesOutLen);
}
