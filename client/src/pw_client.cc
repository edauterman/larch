#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>
#include <string>

#include "pw_client.h"
#include "../../config.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"

using namespace std;
using namespace grpc;

PwClient::PwClient(bool startConn) {
    params = Params_new(P256);
    c = new PasswordClient();
    logAddr = LOG_IP_ADDR;
    if (startConn) {
        stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
    }
}

void PwClient::Initialize() {
    PwInitRequest req;
    PwInitResponse resp;
    ClientContext client_ctx;
    EC_POINT *X = c->StartEnroll();
    uint8_t X_buf[33];
    EC_POINT_point2oct(Params_group(params), X, POINT_CONVERSION_COMPRESSED, X_buf, 33, Params_ctx(params));
    req.set_x(X_buf, 33);

    stub->SendPwInit(&client_ctx, req, &resp);
    
    EC_POINT *recover_pt = EC_POINT_new(Params_group(params));
    EC_POINT_oct2point(Params_group(params), recover_pt, (const unsigned char *)resp.recover_pt().c_str(), 33, Params_ctx(params));
    c->FinishEnroll(recover_pt);
}
