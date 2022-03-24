#include <stdlib.h>
#include <stdio.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <emp-tool/emp-tool.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"
#include "../agent/params.cc"
#include "../agent/u2f.h"
#include "../zkboo/src/proof.h"
#include "../zkboo/src/verifier.h"

#include "log.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

//using json = nlohmann::json;
using namespace std;
using namespace emp;

LogServer::LogServer() {
    params = Params_new(P256);
};

void LogServer::GenerateKeyPair(uint8_t *x_out, uint8_t *y_out) {
    EC_KEY *key = EC_KEY_new();
    pkey = EVP_PKEY_new();

    EC_KEY_set_group(key, params->group);
    EC_KEY_generate_key(key);
    //EC_KEY_set_private_key(key, sk_map[string((const char *)key_handle, MAX_KH_SIZE)]);
    EVP_PKEY_assign_EC_KEY(pkey, key);

    const EC_POINT *pk = EC_KEY_get0_public_key(key);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
    BN_bn2bin(x, x_out);
    BN_bn2bin(y, y_out);
};

void LogServer::VerifyProofAndSign(uint8_t *proof_bytes, uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *sig_out, unsigned int *sig_len) {
    Proof proof;
    proof.Deserialize(proof_bytes, numRands);

    uint64_t low = *((uint64_t *)iv_bytes);
    uint64_t high = *(((uint64_t *)iv_bytes) + 1);
    __m128i iv = makeBlock(low, high);
           
    // TODO somehow need to check key_comm matches things? and that ct is correctly in the witness? 
    bool check = VerifyCtCircuit(proof, iv, m_len, challenge_len);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(mdctx);
    EVP_SignInit(mdctx, EVP_sha256());
    EVP_SignUpdate(mdctx, challenge, challenge_len);
    EVP_SignFinal(mdctx, sig_out, sig_len, pkey);
};

class LogServiceImpl final : public Log::Service {
    public:
        LogServer &server;

        LogServiceImpl(LogServer &server) : server(server) {}

        Status SendReg(ServerContext *context, const RegRequest *req, RegResponse *resp) override {
            printf("Received registration request\n");
            uint8_t x[P256_SCALAR_SIZE];
            uint8_t y[P256_SCALAR_SIZE];
            server.GenerateKeyPair(x, y);
            resp->set_pk_x(x, P256_SCALAR_SIZE);
            resp->set_pk_y(x, P256_SCALAR_SIZE);
            return Status::OK;
        }

        Status SendAuth(ServerContext *context, const AuthRequest *req, AuthResponse *resp) override {
            printf("Received auth request\n");
            uint8_t sig[MAX_ECDSA_SIG_SIZE];
            unsigned int sig_len = 0;
            string proofStr = req->proof();
            string challengeStr = req->challenge();
            string ctStr = req->ct();
            string ivStr = req->iv();
            server.VerifyProofAndSign((uint8_t *)req->proof().c_str(), (uint8_t *)req->challenge().c_str(), (uint8_t *)req->ct().c_str(), (uint8_t *)req->iv().c_str(), sig, &sig_len);
            resp->set_sig(sig, sig_len);
            return Status::OK;
        }
};

void runServer(string bindAddr) {
    LogServer s;
    LogServiceImpl logService(s);

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder logBuilder;
    logBuilder.SetMaxReceiveMessageSize(-1);
    logBuilder.AddListeningPort(bindAddr, grpc::InsecureServerCredentials());
    logBuilder.RegisterService(&logService);
    unique_ptr<Server> logServer(logBuilder.BuildAndStart());
}

int main(int argc, char *argv[]) {
    /*ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;*/

    string bindAddr = "0.0.0.0:"; // + string(config[PORT]);

    runServer(bindAddr);

	printf("Hello world\n");
}
