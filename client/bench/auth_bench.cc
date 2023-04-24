#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <fstream>

#include "../src/u2f.h"
#include "../../zkboo/utils/timer.h"
#include "../../crypto/src/params.h"
#include "../../crypto/src/common.h"
#include "../../crypto/src/sigs.h"
#include "../src/client.h"

using namespace grpc;

int main(int argc, char *argv[]) {
    string ip_addr(argv[1]);
    string out_file(argv[2]);
    Client *c = new Client(ip_addr);
    int iters = 100;
    uint8_t app_id[32];
    uint8_t challenge[32];
    uint8_t key_handle[32];
    uint8_t flags;
    uint32_t ctr;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    uint8_t cert_sig[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    //c->ReadFromStorage();
    c->Initialize();
    ofstream f;
    f.open(out_file);
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; i++) {
        c->Authenticate(app_id, 32, challenge, key_handle, &flags, &ctr, sig_out, true);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    uint32_t logMs = (double)c->GetLogMs() / (double)iters;
    double totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() / (double)iters;
    cout << "Total ms (100)" << totalMs << endl;
    cout << "Log ms (100)" << logMs << endl;
    f << logMs << endl;
    f << totalMs << endl;
    f.close();
    //c->WriteToStorage();
}
