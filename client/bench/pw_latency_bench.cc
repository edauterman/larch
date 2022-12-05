#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <grpcpp/grpcpp.h>
#include <string>

#include "../../zkboo/utils/timer.h"
#include "../../crypto/src/params.h"
#include "../../crypto/src/common.h"
#include "../src/pw_client.h"

using namespace grpc;
using namespace std;

int main(int argc, char *argv[]) {
    string id = "foo";
    int iters = 1;
    int *lens = (int *)malloc(iters * sizeof(int));
    for (int i = 0; i < iters; i++) {
        lens[i] = 1 << (i + 10);
    }
    Params params = Params_new(P256);
    EC_POINT *pw = EC_POINT_new(Params_group(params));
    PwClient *c = new PwClient();
    c->Initialize();
    int totalRegs = 0;
    INIT_TIMER;
    for (int i = 0; i < iters; i++) {

        // Do registrations
        for (int j = totalRegs; j < lens[i]; j++) {
            Params_rand_point(params, pw);
            c->Register("foo" + to_string(j), pw);
            totalRegs++;
        }

        // Run authentications
        cout << "Starting authentications for " << lens[i] << endl;
        START_TIMER;
        for (int j = 0; j < 1; j++) {
            EC_POINT *pw_test = c->Authenticate(to_string(0));
        }
        STOP_TIMER("authentication (10)");
    }
}
