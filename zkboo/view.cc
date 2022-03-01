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

void CircuitView::Commit(CircuitComm &comm) {
    hash_to_bytes(comm.digest, SHA256_DIGEST_LENGTH, (const uint8_t *)wires.data(), wires.size() * sizeof(uint8_t));
}
