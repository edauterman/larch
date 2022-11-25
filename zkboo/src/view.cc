#include <stdlib.h>
#include <stdio.h>
#include <iostream> 
#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "view.h"
#include "../../crypto/src/params.h"

using namespace std;

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
}

void CircuitView::Commit(CircuitComm &comm, int idx, uint8_t *opening) {
    int len = wires.size() / 8 + 17;
    uint8_t *data = (uint8_t *)malloc(len);
    memset(data, 0, len);
    for (int i = 0; i < wires.size(); i++) {
        data[i/8] = data[i/8] | (GetBit(wires[i], idx) << (i % 8));
    }
    memcpy(data + wires.size() / 8 + 1, opening, 16);
    hash_to_bytes(comm.digest, SHA256_DIGEST_LENGTH, (const uint8_t *)data, len);
    free(data);
}
