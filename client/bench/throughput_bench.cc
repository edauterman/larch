#include <stdlib.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "../src/client.h"
#include "../src/u2f.h"
#include "../../zkboo/utils/timer.h"

#define NUM_WORKERS 20

void init(Client *c) {
    c->Initialize();
}

void makeReqs(Client *c, int *auths, std::chrono::high_resolution_clock::time_point start) {
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    fprintf(stderr, "Starting authentications\n");
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
}

int experiment(string ip_addr, int num_workers) {
    int totalAuths = 0;
    cout << "workers = " << num_workers << endl;
    int *auths = (int *)malloc(num_workers * sizeof(int));
    vector<thread*> workers;
    vector<Client*> clients;
    for (int i = 0; i < num_workers; i++) {
        clients.push_back(new Client(ip_addr));
        workers.push_back(new thread(init, clients[i]));
    }
    for (int i = 0; i < num_workers; i++) {
        workers[i]->join();
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_workers; i++) {
        auths[i] = 0;
        workers[i] = new thread(makeReqs, clients[i], &auths[i], start);
    }
    for (int i = 0; i < num_workers; i++) {
        workers[i]->join();
        cout << "individual auths = " << auths[i] << endl;
        totalAuths += auths[i];
    }
    cout << "total auths: " << totalAuths << endl;
    cout << "throughput : " << (double)totalAuths / 60.0<< endl;
    return totalAuths;
}

int main(int argc, char *argv[]) {
    int workers = 20;
    int maxAuths = 0;
    string ip_addr(argv[1]);
    while (true) {
        int auths = experiment(ip_addr, workers);
        if (auths < maxAuths) {
            cout << "MAX AUTHS = " << maxAuths << endl;
            cout << "workers = " << workers - 5 << endl;
            cout << "throughput = " << (double)maxAuths / 60.0 << endl;
            return 0;
        }
        maxAuths = auths;
        workers += 5;
    }
}
