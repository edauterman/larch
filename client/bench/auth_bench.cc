#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <grpcpp/grpcpp.h>

#include "../src/u2f.h"
#include "../../zkboo/utils/timer.h"
#include "../../crypto/src/params.h"
#include "../../crypto/src/common.h"
#include "../../crypto/src/sigs.h"
#include "../src/client.h"

using namespace grpc;

int main(int argc, char *argv[]) {
    //foo();
    Client *c = new Client();
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    //c->ReadFromStorage();
    c->Initialize();
    fprintf(stderr, "det2f: starting initialize\n");
    INIT_TIMER;
    START_TIMER;
    for (int i = 0; i < 100; i++) {
        c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
    }
    STOP_TIMER("auth time (10)");
    fprintf(stderr, "det2f: finished initialize\n");
    //c->WriteToStorage();
}
