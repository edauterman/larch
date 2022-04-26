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
#include "../crypto/params.h"
#include "../crypto/sigs.h"
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
    auth_ctr = 0;
};

void LogServer::Initialize(const InitRequest *req, uint8_t *pkBuf) {
    memcpy(enc_key_comm, req->key_comm().c_str(), 32);

    printf("copying in hints\n");
    for (int i = 0; i < req->hints_size(); i++) {
        Hint h;
        h.xcoord = BN_bin2bn((uint8_t *)req->hints(i).xcoord().c_str(), req->hints(i).xcoord().size(), NULL);
        h.auth_xcoord = BN_bin2bn((uint8_t *)req->hints(i).auth_xcoord().c_str(), req->hints(i).auth_xcoord().size(), NULL);
        h.r = BN_bin2bn((uint8_t *)req->hints(i).r().c_str(), req->hints(i).r().size(), NULL);
        h.auth_r = BN_bin2bn((uint8_t *)req->hints(i).auth_r().c_str(), req->hints(i).auth_r().size(), NULL);
        h.a = BN_bin2bn((uint8_t *)req->hints(i).a().c_str(), req->hints(i).a().size(), NULL);
        h.b = BN_bin2bn((uint8_t *)req->hints(i).b().c_str(), req->hints(i).b().size(), NULL);
        h.c = BN_bin2bn((uint8_t *)req->hints(i).c().c_str(), req->hints(i).c().size(), NULL);
        h.f = BN_bin2bn((uint8_t *)req->hints(i).f().c_str(), req->hints(i).f().size(), NULL);
        h.g = BN_bin2bn((uint8_t *)req->hints(i).g().c_str(), req->hints(i).g().size(), NULL);
        h.h = BN_bin2bn((uint8_t *)req->hints(i).h().c_str(), req->hints(i).h().size(), NULL);
        h.alpha = BN_bin2bn((uint8_t *)req->hints(i).alpha().c_str(), req->hints(i).alpha().size(), NULL);
        hints.push_back(h);
    }
    printf("done copying in hints\n");

    pk = EC_POINT_new(Params_group(params));
    sk = BN_new();
    //BN_zero(sk);
    //pk = EC_POINT_dup(Params_gen(params), Params_group(params));
    Params_rand_point_exp(params, pk, sk);
    //Params_rand_point_exp(params, pk, sk);
    printf("chose key\n");
    EC_POINT_point2oct(Params_group(params), pk, POINT_CONVERSION_COMPRESSED, pkBuf, 33, Params_ctx(params));
    printf("done choosing log key\n");
}

void LogServer::GenerateKeyPair(uint8_t *x_out, uint8_t *y_out) {
    key = EC_KEY_new();
    pkey = EVP_PKEY_new();
/*    BIGNUM *sk = BN_new();
    EC_POINT *pk_pt = Params_point_new(params);

    Params_rand_point_exp(params, pk_pt, sk);

    EC_KEY_set_group(key, params->group);
    EC_KEY_set_public_key(key, pk_pt);
    EC_KEY_set_private_key(key, sk);
    //EC_KEY_set_private_key(key, sk_map[string((const char *)key_handle, MAX_KH_SIZE)]);
    EVP_PKEY_assign_EC_KEY(pkey, key);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(params->group, pk_pt, x, y, NULL);

    memset(x_out, 0, P256_SCALAR_SIZE);
    memset(y_out, 0, P256_SCALAR_SIZE);
    BN_bn2bin(x, x_out);
    BN_bn2bin(y, y_out);*/
  
    EC_KEY_set_group(key, params->group);
    EC_KEY_generate_key(key);
    //EC_KEY_set_private_key(key, sk_map[string((const char *)key_handle, MAX_KH_SIZE)]);
    EVP_PKEY_assign_EC_KEY(pkey, key);

    const EC_POINT *pk = EC_KEY_get0_public_key(key);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
    memset(x_out, 0, P256_SCALAR_SIZE);
    memset(y_out, 0, P256_SCALAR_SIZE);
    BN_bn2bin(x, x_out);
    BN_bn2bin(y, y_out);
    printf("x = ");
    for (int i = 0; i < P256_SCALAR_SIZE; i++) {
        printf("%x", x_out[i]);
    }
    printf("\n");
    printf("y = ");
    for (int i = 0; i < P256_SCALAR_SIZE; i++) {
        printf("%x", y_out[i]);
    }
    printf("\n");
};

void LogServer::VerifyProofAndSign(uint8_t *proof_bytes, uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *sig_out, unsigned int *sig_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len) {
    Proof proof;
    BIGNUM *d_client = BN_new();
    BIGNUM *e_client = BN_new();
    BIGNUM *d_log = BN_new();
    BIGNUM *e_log = BN_new();
    BIGNUM *auth_d_log = BN_new();
    BIGNUM *auth_e_log = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *hash_bn = BN_new();
    BIGNUM *auth_hash_bn = BN_new();
    BIGNUM *val = BN_new();
    BIGNUM *auth_val = BN_new();
    BIGNUM *out = BN_new();
    BIGNUM *auth_out = BN_new();
    BIGNUM *prod = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    proof.Deserialize(proof_bytes, numRands);

    uint64_t low = *((uint64_t *)iv_bytes);
    uint64_t high = *(((uint64_t *)iv_bytes) + 1);
    __m128i iv = makeBlock(low, high);
    memcpy((uint8_t *)&iv, iv_bytes, 16);
           
    // TODO somehow need to check key_comm matches things? and that ct is correctly in the witness?
    // TODO digest is different?????
    printf("digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    } 
    printf("\n");
    printf("enc_key_comm: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", enc_key_comm[i]);
    } 
    printf("\n");
    printf("ct: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", ct[i]);
    } 
    printf("\n");
    bool check = VerifyCtCircuit(proof, iv, m_len, challenge_len, digest, enc_key_comm, ct);
    if (check) {
        printf("VERIFIED\n");
    } else {
        printf("PROOF FAILED TO VERIFY\n");
        return;
    }
    
    printf("challenge to sign: ");
    for (int i = 0; i < challenge_len / 8; i++) {
        printf("%d ", challenge[i]);
    }
    printf("\n");

    BN_bin2bn(d_in, d_in_len, d_client); 
    BN_bin2bn(e_in, e_in_len, e_client);

    // TODO make sure that digest lines up with value in serialized proof
    BN_bin2bn(digest, 32, hash_bn);
    BN_mod(hash_bn, hash_bn, Params_order(params), ctx);
    printf("converted hash to bn\n");
    printf("message hash bn = %s\n", BN_bn2hex(hash_bn));

    printf("auth ctr = %d\n", auth_ctr);
    printf("x_coord = %s\n", BN_bn2hex(hints[auth_ctr].xcoord));
    BN_mod_mul(val, hints[auth_ctr].xcoord, sk, Params_order(params), ctx);
    //BN_mod_add(val, val, hash_bn, Params_order(params), ctx);
    printf("got sig mul value\n");
    printf("r = %s, a = %s, b = %s, c = %s\n", BN_bn2hex(hints[auth_ctr].r), BN_bn2hex(hints[auth_ctr].a), BN_bn2hex(hints[auth_ctr].b), BN_bn2hex(hints[auth_ctr].c));
    printf("val = %s\n", BN_bn2hex(val));
    
    BN_mod_mul(auth_hash_bn, hash_bn, hints[auth_ctr].alpha, Params_order(params), ctx);
    BN_mod_mul(auth_val, hints[auth_ctr].auth_xcoord, sk, Params_order(params), ctx);
    BN_mod_add(auth_val, auth_val, auth_hash_bn, Params_order(params), ctx);

    BN_mod_sub(d_log, hints[auth_ctr].r, hints[auth_ctr].a, Params_order(params), ctx);
    BN_mod_sub(e_log, val, hints[auth_ctr].b, Params_order(params), ctx);
    printf("computed d and e\n");

    BN_mod_sub(auth_d_log, hints[auth_ctr].auth_r, hints[auth_ctr].f, Params_order(params), ctx);
    BN_mod_sub(auth_e_log, auth_val, hints[auth_ctr].g, Params_order(params), ctx);

    BN_mod_add(d, d_log, d_client, Params_order(params),ctx);
    BN_mod_add(e, e_log, e_client, Params_order(params),ctx);
    printf("d = %s, e = %s\n", BN_bn2hex(d), BN_bn2hex(e));
    printf("combined d and e\n");

    // de + d[b] + e[a] + [c]
    //BN_mod_mul(out, d, e, Params_order(params), ctx);
    //BN_mod_mul(prod, d, hints[auth_ctr].b, Params_order(params), ctx);
    BN_mod_mul(out, d, hints[auth_ctr].b, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, hints[auth_ctr].a, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_add(out, out, hints[auth_ctr].c, Params_order(params), ctx);
    printf("computed s\n");
    printf("share of s = %s\n", BN_bn2hex(out));

    // authenticated value
    // de.\alpha + d[g] + e[f] + [h]
    BN_mod_mul(auth_out, d, e, Params_order(params), ctx);
    BN_mod_mul(auth_out, auth_out, hints[auth_ctr].alpha, Params_order(params), ctx);
    BN_mod_mul(prod, d, hints[auth_ctr].g, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, hints[auth_ctr].f, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, hints[auth_ctr].h, Params_order(params), ctx);

    BN_bn2bin(d_log, d_out);
    *d_len = BN_num_bytes(d_log);

    BN_bn2bin(e_log, e_out);
    *e_len = BN_num_bytes(e_log);

    BN_bn2bin(out, sig_out);
    *sig_len = BN_num_bytes(out);

    auth_ctr++;

/*    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(mdctx);
    EVP_SignInit(mdctx, EVP_sha256());
    printf("challenge len = %d\n", challenge_len / 8);
    EVP_SignUpdate(mdctx, challenge, challenge_len / 8);
    EVP_SignFinal(mdctx, sig_out, sig_len, pkey);*/
};

class LogServiceImpl final : public Log::Service {
    public:
        LogServer *server;

        LogServiceImpl(LogServer *server) : server(server) {}

        Status SendInit(ServerContext *context, const InitRequest *req, InitResponse *resp) override {
            printf("Received initialization request\n");
            uint8_t pkBuf[33];
            server->Initialize(req, pkBuf);
            resp->set_pk(pkBuf, 33);
            printf("Sending initialization response\n");
            return Status::OK;
        }

        Status SendReg(ServerContext *context, const RegRequest *req, RegResponse *resp) override {
            printf("Received registration request\n");
            uint8_t x[P256_SCALAR_SIZE];
            uint8_t y[P256_SCALAR_SIZE];
            server->GenerateKeyPair(x, y);
            resp->set_pk_x(x, P256_SCALAR_SIZE);
            resp->set_pk_y(y, P256_SCALAR_SIZE);
            printf("Sending registration response\n");
            return Status::OK;
        }

        Status SendAuth(ServerContext *context, const AuthRequest *req, AuthResponse *resp) override {
            printf("Received auth request\n");
            uint8_t prod[32];
            unsigned int prod_len = 0;
            unsigned int d_len = 0;
            unsigned int e_len = 0;
            uint8_t d[32];
            uint8_t e[32];
            string proofStr = req->proof();
            string challengeStr = req->challenge();
            string ctStr = req->ct();
            string ivStr = req->iv();
            server->VerifyProofAndSign((uint8_t *)req->proof().c_str(), (uint8_t *)req->challenge().c_str(), (uint8_t *)req->ct().c_str(), (uint8_t *)req->iv().c_str(), (uint8_t *)req->digest().c_str(), (uint8_t *)req->d().c_str(), req->d().size(), (uint8_t *)req->e().c_str(), req->e().size(), prod, &prod_len, d, &d_len, e, &e_len);
            resp->set_prod(prod, prod_len);
            resp->set_d(d, d_len);
            resp->set_e(e, e_len);
            printf("Sending auth response\n");
            return Status::OK;
        }
};

void runServer(string bindAddr) {
    LogServer *s = new LogServer();
    LogServiceImpl logService(s);

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder logBuilder;
    logBuilder.SetMaxReceiveMessageSize(-1);
    logBuilder.AddListeningPort(bindAddr, grpc::InsecureServerCredentials());
    logBuilder.RegisterService(&logService);
    unique_ptr<Server> logServer(logBuilder.BuildAndStart());
    logServer->Wait();
}

int main(int argc, char *argv[]) {
    /*ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;*/

    string bindAddr = "0.0.0.0:12345"; // + string(config[PORT]);

    cout << "going to bind to " << bindAddr << endl;
    runServer(bindAddr);
    cout << "after run server?" << endl;

	printf("Hello world\n");
}
