#include <stdlib.h>
#include <stdio.h>
#include <iostream> 
#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "view.h"
#include "common.h"

using namespace std;

void WireVal::Copy(WireVal &from) {
    memcpy(shares, from.shares, sizeof(uint8_t) * WIRES);
}

void CircuitView::Commit(CircuitComm &comm) {
    uint8_t *buf = (uint8_t *)malloc(wireMap.size() * sizeof(uint8_t));
    map<uint32_t, uint32_t>::iterator it;
    int i = 0;
    for (it = wireMap.begin(); it != wireMap.end(); it++) {
        buf[i] = (uint8_t)it->second;
        i++;
    }
    hash_to_bytes(comm.digest, SHA256_DIGEST_LENGTH, buf, wireMap.size() * sizeof(uint8_t));
    free(buf);
}
