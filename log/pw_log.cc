#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <vector>

#include "../crypto/src/params.h"
#include "../crypto/src/pw.h"
#include "../crypto/src/or_groth.h"
#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"
#include "../config.h"

using namespace std;
using namespace grpc;

class LogServiceImpl final : public Log::Service {
    public:
        Params params;
        PasswordLog *l;
        vector<ElGamalCt *>ctList;
        vector<string>sigList;
        vector<uint64_t>timestampList;
        uint32_t time_ms = 0;

        LogServiceImpl() {}

        Status SendPwInit(ServerContext *context, const PwInitRequest *req, PwInitResponse *resp) override {
            params = Params_new(P256);
            l = new PasswordLog();

            EC_POINT *X = EC_POINT_new(Params_group(params));
            EC_POINT_oct2point(Params_group(params), X, (const unsigned char *)req->x().c_str(), 33, Params_ctx(params));
            EC_POINT *pk = EC_POINT_new(Params_group(params));
            EC_POINT_oct2point(Params_group(params), pk, (const unsigned char *)req->pk().c_str(), 33, Params_ctx(params));
           
            EC_POINT *recover_pt = l->Enroll(X,pk);

            uint8_t recover_pt_buf[33];
            EC_POINT_point2oct(Params_group(params), recover_pt, POINT_CONVERSION_COMPRESSED, recover_pt_buf, 33, Params_ctx(params));
            resp->set_recover_pt(recover_pt_buf, 33);
            return Status::OK;
        }

       Status SendPwRegister(ServerContext *context, const PwRegisterRequest *req, PwRegisterResponse *resp) override {
            EC_POINT *out = l->Register((const unsigned char *)req->id().c_str(), req->id().size());
            uint8_t out_buf[33];
            EC_POINT_point2oct(Params_group(params), out, POINT_CONVERSION_COMPRESSED, out_buf, 33, Params_ctx(params));
            resp->set_out(out_buf, 33);
            return Status::OK;
        }

       Status SendPwAuth(ServerContext *context, const PwAuthRequest *req, PwAuthResponse *resp) override {
            auto t1 = std::chrono::high_resolution_clock::now();
            ElGamalCt *ct = new ElGamalCt(params);
            EC_POINT_oct2point(Params_group(params), ct->R, (const unsigned char *)req->ct_r().c_str(), 33, Params_ctx(params));
            EC_POINT_oct2point(Params_group(params), ct->C, ((const unsigned char *)req->ct_c().c_str()), 33, Params_ctx(params));
            OrProof *or_proof_x = new OrProof();
            or_proof_x->Deserialize(params, (const unsigned char *)req->or_proof_x().c_str());
            OrProof *or_proof_r = new OrProof();
            or_proof_r->Deserialize(params, (const unsigned char *)req->or_proof_r().c_str());

            uint8_t sig_buf[64];
            memcpy(sig_buf, req->sig().c_str(), req->sig().size());
            EC_POINT *out = l->Auth(ct, or_proof_x, or_proof_r, sig_buf);
            uint8_t out_buf[33];
            if (out != NULL) {
                EC_POINT_point2oct(Params_group(params), out, POINT_CONVERSION_COMPRESSED, out_buf, 33, Params_ctx(params));
                resp->set_out(out_buf, 33);
                ctList.push_back(ct);
                sigList.push_back(string(req->sig()));
                timestampList.push_back(time(nullptr));
            }
            auto t2 = std::chrono::high_resolution_clock::now();
            time_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
 
            return Status::OK;
        }

        Status SendPwMs(ServerContext *context, const PwMsRequest *req, PwMsResponse *resp) override {
            resp->set_ms(time_ms);
            time_ms = 0;
            return Status::OK;
        }

        Status SendPwAudit(ServerContext *context, const PwAuditRequest *req, PwAuditResponse *resp) override {
            for (int i = 0; i < ctList.size(); i++) {
                PwTokenMsg *t = resp->add_tokens();
                uint8_t ct_buf_r[33];
                uint8_t ct_buf_c[33];
                EC_POINT_point2oct(Params_group(params), ctList[i]->R, POINT_CONVERSION_COMPRESSED, ct_buf_r, 33, Params_ctx(params));
                EC_POINT_point2oct(Params_group(params), ctList[i]->C, POINT_CONVERSION_COMPRESSED, ct_buf_c, 33, Params_ctx(params));
                t->set_ct_r(ct_buf_r, 33);
                t->set_ct_c(ct_buf_c, 33);
                t->set_sig(sigList[i].c_str(), 64);
                t->set_time(timestampList[i]);
            }
            return Status::OK;
        }
};

void runServer(string bindAddr) {
    LogServiceImpl logService;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder logBuilder;
    logBuilder.SetMaxReceiveMessageSize(-1);
    logBuilder.AddListeningPort(bindAddr, grpc::InsecureServerCredentials());
    logBuilder.RegisterService((Service *)&logService);
    unique_ptr<Server> logServer(logBuilder.BuildAndStart());
    logServer->Wait();
}

int main(int argc, char *argv[]) {
    string bindAddr = LOG_BIND_ADDR; // + string(config[PORT]);

    cout << "going to bind to " << bindAddr << endl;
    runServer(bindAddr);
}
