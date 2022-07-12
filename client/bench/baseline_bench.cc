#include <stdlib.h>
#include <stdio.h>

#include "../src/client.h"
#include "../src/u2f.h"
#include "../../zkboo/utils/timer.h"

int main(int argc, char *argv[]) {
    Client *c = new Client(false);
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    P256_POINT *pk;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    c->ReadFromStorage();
    fprintf(stderr, "det2f: starting initialize\n");
    INIT_TIMER;
    START_TIMER;
    for (int i = 0; i < 10; i++) {
        c->BaselineAuthenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
    }
    STOP_TIMER_US("auth time (100)");
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}
