#include <stdlib.h>
#include <stdio.h>

#include "client.h"
#include "u2f.h"

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
    c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}
