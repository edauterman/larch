#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <grpcpp/grpcpp.h>
#include <string>
#include <iostream>
#include <fstream>

#include "../../zkboo/utils/timer.h"
#include "../../crypto/src/params.h"
#include "../../crypto/src/common.h"
#include "../src/pw_client.h"

using namespace grpc;
using namespace std;

int main(int argc, char *argv[]) {
    string id = "foo";
    int iters = 9;
    int rounds = 10;
    string ip_addr(argv[1]);
    string out_file(argv[2]);
    int *lens = (int *)malloc(iters * sizeof(int));
    for (int i = 0; i < iters; i++) {
        lens[i] = 1 << (i + 1);
    }
    Params params = Params_new(P256);
    EC_POINT *pw = EC_POINT_new(Params_group(params));
    PwClient *c = new PwClient(ip_addr);
    c->Initialize();
    int totalRegs = 0;
    ofstream f;
    f.open(out_file);
    for (int i = 0; i < iters; i++) {

        // Do registrations
        for (int j = totalRegs; j < lens[i]; j++) {
            Params_rand_point(params, pw);
            c->Register(to_string(j), pw);
            totalRegs++;
        }

        // Run authentications
        cout << "Starting authentications for " << lens[i] << endl;
        double clientMs = 0;
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < rounds; j++) {
            EC_POINT *pw_test = c->Authenticate(to_string(0));
            clientMs += c->clientMs;
            c->clientMs = 0;
 
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() / (double)rounds;
        double logMs = (double)c->GetLogMs() / (double)rounds;
        clientMs = (double)clientMs / (double)rounds;
        cout << "Log ms: " << logMs << endl;
        cout << "Client ms: " << clientMs << endl;
        cout << "Total ms: " << totalMs << endl;
        f << logMs << endl;
        f << clientMs << endl;
        f << totalMs << endl;
 
    }
    f.close();
}
