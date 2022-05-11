#include <stdlib.h>
#include <stdio.h>

#include "client.h"
#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"
#include "../zkboo/utils/timer.h"

int main(int argc, char *argv[]) {
    Client *c = new Client();
    BIGNUM *out = BN_new();
    uint8_t digest[32];
    BIGNUM *sk = BN_new();
    AuthRequest req;
    c->ReadFromStorage();
    INIT_TIMER;
    START_TIMER;
    c->ThresholdSign(out, digest, sk, req);
    STOP_TIMER("signature");
    c->WriteToStorage();
}
