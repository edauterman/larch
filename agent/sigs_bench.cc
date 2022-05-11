#include <stdlib.h>
#include <stdio.h>

#include "client.h"
#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"

int main(int argc, char *argv[]) {
    Client *c = new Client();
    BIGNUM *out = BN_new();
    uint8_t digest[32];
    BIGNUM *sk = BN_new();
    AuthRequest req;
    c->ReadFromStorage();
    fprintf(stderr, "det2f: starting initialize\n");
    c->ThresholdSign(out, digest, sk, req);
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}
