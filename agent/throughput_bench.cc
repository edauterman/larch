#include <stdlib.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "client.h"
#include "u2f.h"
#include "../zkboo/utils/timer.h"

#define NUM_WORKERS 10

void makeReqs(int *auths, std::chrono::high_resolution_clock::time_point start) {
    Client *c = new Client();
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    c->Initialize();
    fprintf(stderr, "det2f: starting initialize\n");
    //auto start = std::chrono::high_resolution_clock::now();
    //while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() < 60) {
    while(true) {
        c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() < 60) {
            *auths = *auths + 1;
        } else {
            return;
        }
    }
    printf("returned\n");
    fprintf(stderr, "det2f: finished initialize\n");
}

int main(int argc, char *argv[]) {
    int totalAuths = 0;
    int auths[NUM_WORKERS];
    thread workers[NUM_WORKERS];
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_WORKERS; i++) {
        auths[i] = 0;
        workers[i] = thread(makeReqs, &auths[i], start);
    }
    for (int i = 0; i < NUM_WORKERS; i++) {
        workers[i].join();
        cout << "individual auths = " << auths[i] << endl;
        totalAuths += auths[i];
    }
    cout << "total auths: " << totalAuths << endl;
}
