#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "proof.h"
#include "prover.h"
#include "../../crypto/params.h"
#include "view.h"

static inline void SetWireNum(uint32_t *x, uint32_t wireNum) {
    *x = *x | (wireNum << 1); 
}

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
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
    return GetBit((uint32_t)randomness[gate/8], gate%8);
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
    (*buf)[0] = x & 0xFF;
    (*buf)[1] = (x >> 8) & 0xFF;
    (*buf)[2] = (x >> 16) & 0xFF;
    (*buf)[3] = (x >> 24) & 0xFF;
    *buf += 4;
}

void Proof::SerializeBit(uint32_t x, uint8_t **buf, int *idx) {
/*    if (x != 0 && x != 1) {
        printf("ERROR: serializing %d as bit\n", x);
    }*/
    if (x & 1 == 1) {
        (*buf)[0] = (*buf)[0] | (1 << *idx);
    }
    if (*idx == 7) {
        *idx = 0;
        *buf += 1;
    } else {
        *idx += 1;
    }
}

uint32_t Proof::DeserializeInt32(uint8_t **buf) {
    uint32_t out = (*buf)[0] | ((*buf)[1] << 8) | ((*buf)[2] << 16) | ((*buf)[3] << 24);
    *buf += 4;
    return out;
}

uint32_t Proof::DeserializeBit(uint8_t **buf, int *idx) {
    uint32_t ret = ((*buf)[0] & (1 << *idx)) >> (*idx);
    assert(ret == 0 || ret == 1);
    if (*idx == 7) {
        *idx = 0;
        *buf += 1;
    } else {
        *idx += 1;
    }
    return ret;
}

uint8_t *Proof::Serialize(int *out_len) {
   int bytesOutLen = outLen < 8 ? 1 : outLen / 8; 
   int mLen = 256;
   //int mLen = (wLen - 256 - 128 - 128 - 256) / 2;
   int len = (sizeof(uint32_t) * 4) +                       // wLen and outLen and idx and numWires
       (SHA256_DIGEST_LENGTH * 3) +                         // CircuitComm
       ((views[0]->wires.size() * 2) / 8) +                 // views
       (16 * 2) +                                           // seeds for RandomSource
       ((wLen * 2) / 8) +                                   // shares of witness
       ((outLen * 3) / 8) +                                 // shares of output
       (bytesOutLen) +                                      // output raw values
       (((mLen + 256 + 256) * 3) / 8) +                     // shares of public input
       5;                                                   
    fprintf(stderr, "zkboo: allocating %d bytes\n", len);
    uint8_t *out = (uint8_t *)malloc(len);
    memset(out, 0, len);
    if (out == NULL) printf("NULL alloc\n");
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
    int bitIdx = 0;
    // views
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < numWires; j++) {
            SerializeBit(views[i]->wires[j], &ptr, &bitIdx);
            //SerializeInt32(views[i]->wires[j], &ptr);
        }
    }
    ptr += 1;
    // randomness seeds
    for (int i = 0; i < 2; i++) {
        memcpy(ptr, rands[i]->seed, 16);
        ptr += 16;
    }
    // witness shares
    bitIdx = 0;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < wLen; j++) {
            SerializeBit(w[i][j], &ptr, &bitIdx);
            //SerializeInt32(w[i][j], &ptr);
        }
    }
    // output shares
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < outLen; j++) {
            SerializeBit(outShares[i][j], &ptr, &bitIdx);
            //SerializeInt32(outShares[i][j], &ptr);
        }
    }
    ptr += 1;
    // output
    memcpy(ptr, out, bytesOutLen);
    ptr += bytesOutLen;
    // pubInShares
    bitIdx = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < mLen + 256 + 256; j++) {
            SerializeBit(pubInShares[i][j], &ptr, &bitIdx);
            //SerializeInt32(pubInShares[i][j], &ptr);
        }
    }

    *out_len = len;
    return out;
}

void Proof::Deserialize(uint8_t *buf, int numRands) {
    uint8_t *ptr = buf;
    wLen = DeserializeInt32(&ptr);
    int mLen = 256;
    //int mLen = (wLen - 256 - 128 - 128 - 256) / 2;
    outLen = DeserializeInt32(&ptr);
    idx = DeserializeInt32(&ptr);
    uint32_t numWires = DeserializeInt32(&ptr);
    int bytesOutLen = outLen < 8 ? 1 : outLen / 8; 
    // commitments
    for (int i = 0; i < 3; i++) {
        memcpy(comms[i].digest, ptr, 32);
        ptr += 32;
    }
    int bitIdx = 0;
    // views
    for (int i = 0; i < 2; i++) {
        views[i] = new CircuitView();
        for (int j = 0; j < numWires; j++) {
            uint32_t val = DeserializeBit(&ptr, &bitIdx);
            //SetWireNum(&val, j + wLen);
            views[i]->wires.push_back(val);
            //views[i]->wires.push_back(DeserializeBit(&ptr, &bitIdx));
            //views[i]->wires.push_back(DeserializeInt32(&ptr));
        }
    }
    ptr += 1;
    // randomness seeds
    for (int i = 0; i < 2; i++) {
        rands[i] = new RandomSource(ptr, numRands);
        ptr += 16;
        // TODO expand seed
    }
    // witness shares
    bitIdx = 0;
    for (int i = 0; i < 2; i++) {
        w[i] = (uint32_t *)malloc(sizeof(uint32_t) * wLen);
        for (int j = 0; j < wLen; j++) {
            uint32_t val = DeserializeBit(&ptr, &bitIdx);
            //SetWireNum(&val, j);
            w[i][j] = val;
            //w[i][j] = DeserializeBit(&ptr, &bitIdx);
            //w[i][j] = DeserializeInt32(&ptr);
        }
    }
    // output shares
    for (int i = 0; i < 3; i++) {
        outShares[i] = (uint32_t *)malloc(sizeof(uint32_t) * outLen);
        for (int j = 0; j < outLen; j++) {
            outShares[i][j] = DeserializeBit(&ptr, &bitIdx);
            //outShares[i][j] = DeserializeInt32(&ptr);
        }
    }
    ptr += 1;
    // output
    out = (uint8_t *)malloc(bytesOutLen);
    memcpy(out, ptr, bytesOutLen);
    ptr += bytesOutLen;
    // pubInShares
    bitIdx = 0;
    for (int i = 0; i < 3; i++) {
        pubInShares[i] = (uint32_t *)malloc((mLen + 256 + 256) * sizeof(uint32_t));
        for (int j = 0; j < 256; j++) {
            pubInShares[i][j] = DeserializeBit(&ptr, &bitIdx);
            //SetWireNum(&pubInShares[i][j], mLen + j);
            //pubInShares[i][j] = DeserializeInt32(&ptr);
        }
        for (int j = 0; j < 256; j++) {
            pubInShares[i][j + 256] = DeserializeBit(&ptr, &bitIdx);
            //SetWireNum(&pubInShares[i][j + 256], 2 * mLen + 256 + 128 + 128 + j);
            //pubInShares[i][j] = DeserializeInt32(&ptr);
        }
        for (int j = 0; j < mLen; j++) {
            pubInShares[i][j + 256 + 256] = DeserializeBit(&ptr, &bitIdx);
            //SetWireNum(&pubInShares[i][j + 256 + 256], mLen + 256 + j);
            //pubInShares[i][j] = DeserializeInt32(&ptr);
        }
 
    }
}
