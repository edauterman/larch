#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>
#include <string>

#include "pw_client.h"
#include "../../crypto/src/or_groth.h"
#include "../../crypto/src/sigs.h"
#include "../../config.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"

using namespace std;
using namespace grpc;

PwClient::PwClient(string ip_addr, bool startConn) {
    c = new PasswordClient();
    logAddr = ip_addr + ":12345";
    ctr = 0;
    if (startConn) {
        stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
    }
}

void PwClient::Initialize() {
    PwInitRequest req;
    PwInitResponse resp;
    ClientContext client_ctx;
    EC_POINT *X = EC_POINT_new(Params_group(params));
    EC_POINT *sig_pk = EC_POINT_new(Params_group(params));
    c->StartEnroll(X, sig_pk);
    uint8_t X_buf[33];
    EC_POINT_point2oct(Params_group(c->params), X, POINT_CONVERSION_COMPRESSED, X_buf, 33, Params_ctx(c->params));
    req.set_x(X_buf, 33);
    uint8_t pk_buf[33];
    EC_POINT_point2oct(Params_group(c->params), sig_pk, POINT_CONVERSION_COMPRESSED, pk_buf, 33, Params_ctx(c->params));
    req.set_pk(pk_buf, 33);

    stub->SendPwInit(&client_ctx, req, &resp);
    
    EC_POINT *recover_pt = EC_POINT_new(Params_group(c->params));
    EC_POINT_oct2point(Params_group(c->params), recover_pt, (const unsigned char *)resp.recover_pt().c_str(), 33, Params_ctx(c->params));
    c->FinishEnroll(recover_pt);
}

void PwClient::Register(string id, EC_POINT *pw) {
    PwRegisterRequest req;
    PwRegisterResponse resp;
    ClientContext client_ctx;

    c->StartRegister((const uint8_t *)id.c_str(), id.size());
    req.set_id(id);

    stub->SendPwRegister(&client_ctx, req, &resp);

    EC_POINT *out = EC_POINT_new(Params_group(c->params));
    EC_POINT_oct2point(Params_group(c->params), out, (const unsigned char *)resp.out().c_str(), 33, Params_ctx(c->params));
 
    c->FinishRegister(out, pw);
    orderMap[id] = ctr;
    ctr++;
}

EC_POINT *PwClient::Authenticate(string id) {
    PwAuthRequest req;
    PwAuthResponse resp;
    ClientContext client_ctx;
    auto t1 = std::chrono::high_resolution_clock::now();
    ElGamalCt *ct = new ElGamalCt(c->params);
    BIGNUM *r = BN_new();
    OrProof *or_proof_x;
    OrProof *or_proof_r;
    uint8_t *sig_buf;
    unsigned int sig_len;

    c->StartAuth(orderMap[id], (const uint8_t *)id.c_str(), id.size(), ct, &or_proof_x, &or_proof_r, r, &sig_buf, &sig_len);
    uint8_t ct_buf_r[33];
    uint8_t ct_buf_c[33];
    EC_POINT_point2oct(Params_group(c->params), ct->R, POINT_CONVERSION_COMPRESSED, ct_buf_r, 33, Params_ctx(c->params));
    EC_POINT_point2oct(Params_group(c->params), ct->C, POINT_CONVERSION_COMPRESSED, ct_buf_c, 33, Params_ctx(c->params));
    req.set_ct_r(ct_buf_r, 33);
    req.set_ct_c(ct_buf_c, 33);
 
    uint8_t *or_proof_x_buf;
    int len_x;
    or_proof_x->Serialize(c->params, &or_proof_x_buf, &len_x);
    req.set_or_proof_x(or_proof_x_buf, len_x);
    uint8_t *or_proof_r_buf;
    int len_r;
    or_proof_r->Serialize(c->params, &or_proof_r_buf, &len_r);
    req.set_or_proof_r(or_proof_r_buf, len_r);

    req.set_sig(sig_buf, sig_len);
    free(sig_buf);
    auto t2 = std::chrono::high_resolution_clock::now();

    stub->SendPwAuth(&client_ctx, req, &resp);
    auto t3 = std::chrono::high_resolution_clock::now();

    EC_POINT *out = EC_POINT_new(Params_group(c->params));
    EC_POINT_oct2point(Params_group(c->params), out, (const unsigned char *)resp.out().c_str(), 33, Params_ctx(c->params));
 
    EC_POINT *pw = c->FinishAuth(orderMap[id], out, r);
    auto t4 = std::chrono::high_resolution_clock::now();
    
    clientMs = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() + std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();

    return pw;
}

void PwClient::PrintAuditLog() {
    PwAuditRequest req;
    PwAuditResponse resp;
    ClientContext client_ctx;
    stub->SendPwAudit(&client_ctx, req, &resp);
    ElGamalCt *ct = new ElGamalCt(c->params);
    uint8_t sig_buf[66];
    for (uint32_t i = 0; i < resp.tokens_size(); i++) {
        EC_POINT_oct2point(Params_group(c->params), ct->R, (const unsigned char *)resp.tokens(i).ct_r().c_str(), 33, Params_ctx(params));
        EC_POINT_oct2point(Params_group(c->params), ct->C, (const unsigned char *)resp.tokens(i).ct_c().c_str(), 33, Params_ctx(params));
        memcpy(sig_buf, resp.tokens(i).sig_buf().c_str(), resp.tokens(i).sig().size());
        PrintLogEntry(ct, sig_buf);
    }

}

uint32_t PwClient::GetLogMs() {
    PwMsRequest req;
    PwMsResponse resp;
    ClientContext client_ctx;
    stub->SendPwMs(&client_ctx, req, &resp);
    return resp.ms();
}
