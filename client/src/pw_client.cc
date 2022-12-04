#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>
#include <string>

#include "pw_client.h"
#include "../../crypto/src/or_groth.h"
#include "../../config.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"

using namespace std;
using namespace grpc;

PwClient::PwClient(bool startConn) {
    params = Params_new(P256);
    c = new PasswordClient();
    logAddr = LOG_IP_ADDR;
    ctr = 0;
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

void PwClient::Register(string id, EC_POINT *pw) {
    PwRegisterRequest req;
    PwRegisterResponse resp;
    ClientContext client_ctx;

    c->StartRegister((const uint8_t *)id.c_str(), id.size());
    req.set_id(id);

    stub->SendPwRegister(&client_ctx, req, &resp);

    EC_POINT *out = EC_POINT_new(Params_group(params));
    EC_POINT_oct2point(Params_group(params), out, (const unsigned char *)resp.out().c_str(), 33, Params_ctx(params));
    c->FinishRegister(out, pw);
    orderMap[id] = ctr;
    ctr++;
}

EC_POINT *PwClient::Authenticate(string id) {
    PwAuthRequest req;
    PwAuthResponse resp;
    ClientContext client_ctx;
    ElGamalCt *ct = new ElGamalCt(params);
    BIGNUM *r = BN_new();
    OrProof *or_proof_x;
    OrProof *or_proof_r;

    c->StartAuth(orderMap[id], (const uint8_t *)id.c_str(), id.size(), ct, &or_proof_x, &or_proof_r, r);
    uint8_t ct_buf[66];
    EC_POINT_point2oct(Params_group(params), ct->R, POINT_CONVERSION_COMPRESSED, ct_buf, 33, Params_ctx(params));
    EC_POINT_point2oct(Params_group(params), ct->C, POINT_CONVERSION_COMPRESSED, ct_buf + 33, 33, Params_ctx(params));
    req.set_ct(ct_buf, 66);
    uint8_t *or_proof_x_buf;
    int len_x;
    or_proof_x->Serialize(params, &or_proof_x_buf, &len_x);
    req.set_or_proof_x(or_proof_x_buf, len_x);
    uint8_t *or_proof_r_buf;
    int len_r;
    or_proof_r->Serialize(params, &or_proof_r_buf, &len_r);
    req.set_or_proof_r(or_proof_x_buf, len_r);

    stub->SendPwAuth(&client_ctx, req, &resp);

    EC_POINT *out = EC_POINT_new(Params_group(params));
    EC_POINT_oct2point(Params_group(params), out, (const unsigned char *)resp.out().c_str(), 33, Params_ctx(params));
    EC_POINT *pw = c->FinishAuth(orderMap[id], out, r);
    return pw;
}
