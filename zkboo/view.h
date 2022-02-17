#ifndef _VIEW_H_
#define _VIEW_H_

#include <vector>
#include <stdint.h>
#include <openssl/sha.h>

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
        vector<uint64_t> wireShares;

        void Commit(CircuitComm &comm);
};

class CircuitViews {
    public:
        vector<WireVal> wires;
        CircuitView GetView(int idx);
};

#endif
