#include <stdlib.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "view.h"
#include "common.h"

void WireVal::Copy(WireVal &from) {
    memcpy(shares, from.shares, sizeof(uint8_t) * WIRES);
}

CircuitView CircuitViews::GetView(int idx) {
    CircuitView v;
    for (int i = 0; i < wires.size(); i++) {
        v.wireShares.push_back(wires[i].shares[idx]);
    }
}

void CircuitView::Commit(CircuitComm &comm) {
    uint8_t *buf = (uint8_t *)malloc(wireShares.size() * sizeof(uint8_t));
    for (int j = 0; j < wireShares.size(); j++) {
        buf[j] = wireShares[j];
    }
    hash_to_bytes(comm.digest, SHA256_DIGEST_LENGTH, buf, wireShares.size() * sizeof(uint8_t));
}
