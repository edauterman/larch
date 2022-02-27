#ifndef _VIEW_H_
#define _VIEW_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>
#include <map>

#define WIRES 3

using namespace std;

class WireVal {
    public:
        uint8_t shares[WIRES];

        void Copy(WireVal &from);
};

class CircuitComm {
    public:
        uint8_t digest[SHA256_DIGEST_LENGTH];
};

class CircuitView {
    public:
        map<uint32_t, uint32_t> wireMap;

        void Commit(CircuitComm &comm);
};

#endif
