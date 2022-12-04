#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <grpcpp/grpcpp.h>

#include "../../zkboo/utils/timer.h"
#include "../../crypto/src/params.h"
#include "../../crypto/src/common.h"
#include "../src/pw_client.h"

using namespace grpc;

int main(int argc, char *argv[]) {
    string id = "foo";
    Params params = Params_new(P256);
    EC_POINT *pw = EC_POINT_new(Params_group(params));
    PwClient *c = new PwClient();
    c->Initialize();
    c->Register(id, pw);
    EC_POINT *pw_test = c->Authenticate(id);
    int res = EC_POINT_cmp(Params_group(params), pw, pw_test, Params_ctx(params));
    if (res == 0) {
        cout << "Test passed." << endl;
    } else {
        cout << "ERROR: returned incorrect pw" << endl;
    }
}
