#include <stdlib.h>
#include <stdio.h>

#include "client.h"
#include "u2f.h"
#include "../zkboo/utils/timer.h"

void makeReqs(int *auths) {
    Client *c = new Client();
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    c->ReadFromStorage();
    fprintf(stderr, "det2f: starting initialize\n");
    auto start = std::chrono::high_resolution_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count < 60) {
        c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
        *auths = *auths + 1;
    }
    printf("returned\n");
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}

int main(int argc, char *argv[]) {
    Client *c = new Client();
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
    c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
    printf("returned\n");
    STOP_TIMER("auth time");
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}
