#include <stdlib.h>
#include <stdio.h>

#include "../src/client.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"
#include "../../zkboo/utils/timer.h"

int main(int argc, char *argv[]) {
    string ip_addr(argv[1]);
    Client *c = new Client(ip_addr, true);
    BIGNUM *out = BN_new();
    uint8_t digest[32];
    BIGNUM *sk = BN_new();
    AuthRequest req;
    c->Initialize();
    INIT_TIMER;
    START_TIMER;
    for (int i = 0; i < 100; i++) {
        c->ThresholdSign(out, digest, sk, req);
    }
    STOP_TIMER("signature (100 reps)");
}
