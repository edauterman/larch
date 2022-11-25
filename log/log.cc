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
#include <openssl/rand.h>

#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"
#include "../crypto/src/params.h"
#include "../crypto/src/sigs.h"
#include "../client/src/u2f.h"
#include "../zkboo/src/proof.h"
#include "../zkboo/src/verifier.h"
#include "../zkboo/utils/timer.h"
#include "../config.h"

#include "log.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using namespace std;
using namespace emp;

Token::Token(uint8_t *ct_in, uint8_t *iv_in, uint8_t *sig_in, unsigned int sig_len) {
    memcpy(ct, ct_in, SHA256_DIGEST_LENGTH);
    memcpy(iv, iv_in, 16);
    memset(sig, 0, MAX_ECDSA_SIG_SIZE);
    memcpy(sig, sig_in, sig_len);
}

AuthState::AuthState(BIGNUM *check_d_in, uint8_t *r_in, BIGNUM *out_in) {
    check_d = check_d_in;
    memcpy(r, r_in, 16);
    out = out_in;
}

InitState::InitState() {}

LogServer::LogServer(bool onlySigs_in) {
    params = Params_new(P256);
    onlySigs = onlySigs_in;
};

void LogServer::GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *alpha, uint8_t *seed_in) {
    uint64_t ctr = i * 4; 
    GetPreprocessValue(ctr, r, seed_in, params);
    GetPreprocessValue(ctr + 1, a, seed_in, params);
    GetPreprocessValue(ctr + 2, b, seed_in, params);
    GetPreprocessValue(ctr + 3, alpha, seed_in, params);
}

void LogServer::Initialize(const InitRequest *req, uint8_t *pkBuf) {
    InitState *initSt = new InitState();
    memcpy(initSt->enc_key_comm, req->key_comm().c_str(), 32);

    for (int i = 0; i < req->hints_size(); i++) {
        Hint h;
        h.xcoord = BN_bin2bn((uint8_t *)req->hints(i).xcoord().c_str(), req->hints(i).xcoord().size(), NULL);
        h.auth_r = BN_bin2bn((uint8_t *)req->hints(i).auth_r().c_str(), req->hints(i).auth_r().size(), NULL);
        h.c = BN_bin2bn((uint8_t *)req->hints(i).c().c_str(), req->hints(i).c().size(), NULL);
        h.f = BN_bin2bn((uint8_t *)req->hints(i).f().c_str(), req->hints(i).f().size(), NULL);
        h.g = BN_bin2bn((uint8_t *)req->hints(i).g().c_str(), req->hints(i).g().size(), NULL);
        h.h = BN_bin2bn((uint8_t *)req->hints(i).h().c_str(), req->hints(i).h().size(), NULL);
        initSt->hints.push_back(h);
    }
    initSt->auth_pk = EC_POINT_new(Params_group(params));
    memcpy(initSt->log_seed, (uint8_t *)req->log_seed().c_str(), 16);
    EC_POINT_oct2point(Params_group(params), initSt->auth_pk, (uint8_t *)req->auth_pk().c_str(), 33, Params_ctx(params));

    initSt->pk = EC_POINT_new(Params_group(params));
    initSt->sk = BN_new();
    Params_rand_point_exp(params, initSt->pk, initSt->sk);
    memset(pkBuf, 0, 33);
    EC_POINT_point2oct(Params_group(params), initSt->pk, POINT_CONVERSION_COMPRESSED, pkBuf, 33, Params_ctx(params));
    initSt->auth_ctr = 0;

    clientMap[req->id()] = initSt;
}

void LogServer::VerifyProofAndSign(uint32_t id, uint8_t *proof_bytes[NUM_ROUNDS], uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *auth_sig, unsigned int auth_sig_len, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len, uint8_t *cm_check_d, uint32_t *sessionCtr) {
    Proof proof[NUM_ROUNDS];
    BIGNUM *d_client = BN_new();
    BIGNUM *e_client = BN_new();
    BIGNUM *d_log = BN_new();
    BIGNUM *e_log = BN_new();
    BIGNUM *auth_d_log = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *hash_bn = BN_new();
    BIGNUM *out = BN_new();
    BIGNUM *prod = BN_new();
    BIGNUM *check_d = BN_new();
    BIGNUM *term1 = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *alpha = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    uint32_t auth_ctr = clientMap[id]->auth_ctr;

    uint64_t low = *((uint64_t *)iv_bytes);
    uint64_t high = *(((uint64_t *)iv_bytes) + 1);
    __m128i iv = makeBlock(low, high);
    memcpy((uint8_t *)&iv, iv_bytes, 16);
           
    bool final_check = true;
    bool check[NUM_ROUNDS];
    thread workers[NUM_ROUNDS];
    INIT_TIMER;
    if (!onlySigs) {
        START_TIMER;
        for (int i = 0; i < NUM_ROUNDS; i++) {
            proof[i].Deserialize(proof_bytes[i], numRands);
            workers[i] = thread(VerifyCtCircuit, &proof[i], iv, m_len, challenge_len, digest, clientMap[id]->enc_key_comm, ct, &check[i]);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers[i].join();
            final_check = final_check && check[i];
        }
        STOP_TIMER("proofs");
        if (final_check) {
            printf("VERIFIED\n");
        } else {
            printf("PROOF FAILED TO VERIFY\n");
            return;
        }
    }

    GetPreprocessValueSet(auth_ctr, r, a, b, alpha, clientMap[id]->log_seed);

    BN_bin2bn(d_in, d_in_len, d_client);
    BN_bin2bn(e_in, e_in_len, e_client);

    BN_bin2bn(digest, 32, hash_bn);
    BN_mod(hash_bn, hash_bn, Params_order(params), ctx);

    BN_mod_sub(d_log, r, a, Params_order(params), ctx);
    BN_mod_sub(e_log, clientMap[id]->sk, b, Params_order(params), ctx);

    BN_mod_sub(auth_d_log, clientMap[id]->hints[auth_ctr].auth_r, clientMap[id]->hints[auth_ctr].f, Params_order(params), ctx);

    BN_mod_add(d, d_log, d_client, Params_order(params),ctx);
    BN_mod_add(e, e_log, e_client, Params_order(params),ctx);

    // de + d[b] + e[a] + [c]
    BN_mod_mul(out, d, b, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, a, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_add(out, out, clientMap[id]->hints[auth_ctr].c, Params_order(params), ctx);

    // out
    // [r].H(m) + x.[out]
    BN_mod_mul(term1, hash_bn, r, Params_order(params), ctx);
    BN_mod_mul(out, out, clientMap[id]->hints[auth_ctr].xcoord, Params_order(params), ctx);
    BN_mod_add(out, out, term1, Params_order(params), ctx);


    BN_bn2bin(d_log, d_out);
    *d_len = BN_num_bytes(d_log);

    BN_bn2bin(e_log, e_out);
    *e_len = BN_num_bytes(e_log);

    *sessionCtr = rand();
    BN_mod_mul(check_d, alpha, d, Params_order(params), ctx);
    BN_mod_sub(check_d, auth_d_log, check_d, Params_order(params), ctx);
    uint8_t r_buf[16];
    uint8_t check_d_buf[32];
    int len = BN_bn2bin(check_d, check_d_buf);
    RAND_bytes(r_buf, 16);
    Commit(cm_check_d, check_d_buf, len, r_buf);
    AuthState *state = new AuthState(check_d, r_buf, out);
    saveMap[*sessionCtr] = state;

    clientMap[id]->auth_ctr++;
    
    if (!onlySigs) {
        Token *token = new Token(ct, iv_bytes, auth_sig, auth_sig_len);
        tokenMap[id] = token;

        // TODO move earlier to abort if check fails
        uint8_t auth_input[48];
        memcpy(auth_input, iv_bytes, 16);
        memcpy(auth_input + 16, ct, 32);
        EC_KEY *key = EC_KEY_new();
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EC_KEY_new_by_curve_name(415);
        EC_KEY_set_public_key(key, clientMap[id]->auth_pk);
        EVP_PKEY_assign_EC_KEY(pkey, key);
        EVP_VerifyInit(mdctx, EVP_sha256());
        EVP_VerifyUpdate(mdctx, auth_input, 48);
        int ver = EVP_VerifyFinal(mdctx, auth_sig, auth_sig_len, pkey);
    }

    if (d_client) BN_free(d_client);
    if (e_client) BN_free(e_client);
    if (d_log) BN_free(d_log);
    if (e_log) BN_free(e_log);
    if (auth_d_log) BN_free(auth_d_log);
    if (d) BN_free(d);
    if (e) BN_free(e);
    if (hash_bn) BN_free(hash_bn);
    if (prod) BN_free(prod);
    if (term1) BN_free(term1);
    if (r) BN_free(r);
    if (a) BN_free(a);
    if (b) BN_free(b);
    if (alpha) BN_free(alpha);
    if (ctx) BN_CTX_free(ctx);

};

void LogServer::FinishSign(uint32_t sessionCtr, uint8_t *cm_check_d, uint8_t *check_d_buf_out, unsigned int *check_d_buf_len, uint8_t *check_d_open) {

    memcpy(saveMap[sessionCtr]->other_cm_check_d, cm_check_d, 32);
    *check_d_buf_len = BN_bn2bin(saveMap[sessionCtr]->check_d, check_d_buf_out);
    memcpy(check_d_open, saveMap[sessionCtr]->r, 16);
}

void LogServer::FinalSign(uint32_t sessionCtr, uint8_t *check_d_buf, unsigned int check_d_len, uint8_t *check_d_open, uint8_t *final_out, unsigned int *final_out_len) {
    BIGNUM *check_d_client = BN_new();
    BIGNUM *sum = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn(check_d_buf, check_d_len, check_d_client);

    BN_mod_add(sum, check_d_client, saveMap[sessionCtr]->check_d, Params_order(params), ctx);
    if (!BN_is_zero(sum)) {
        fprintf(stderr, "ERROR: MAC tag for d doesn't verify %s %s -> %s\n", BN_bn2hex(check_d_client), BN_bn2hex(saveMap[sessionCtr]->check_d), BN_bn2hex(sum));
        *final_out_len = 0;
        return;
    }

    uint8_t check_cm[32];
    Commit(check_cm, check_d_buf, check_d_len, check_d_open);
    if (memcmp(check_cm, saveMap[sessionCtr]->other_cm_check_d, 32) != 0) {
        fprintf(stderr, "ERROR: commitment doesn't open correctly = %s\n", check_d_len);
        *final_out_len = 0;
    }
    
    *final_out_len = BN_bn2bin(saveMap[sessionCtr]->out, final_out);
    
    if (check_d_client) BN_free(check_d_client);
    if (sum) BN_free(sum);
    if (ctx) BN_CTX_free(ctx);
}


class LogServiceImpl final : public Log::Service {
    public:
        LogServer *server;
        bool onlySigs;

        LogServiceImpl(LogServer *server, bool onlySigs_in) : server(server), onlySigs(onlySigs_in) {}

        Status SendInit(ServerContext *context, const InitRequest *req, InitResponse *resp) override {
            uint8_t pkBuf[33];
            server->Initialize(req, pkBuf);
            resp->set_pk(pkBuf, 33);
            return Status::OK;
        }

        Status SendAuth(ServerContext *context, const AuthRequest *req, AuthResponse *resp) override {
            uint8_t prod[32];
            unsigned int prod_len = 0;
            unsigned int d_len = 0;
            unsigned int e_len = 0;
            uint8_t d[32];
            uint8_t e[32];
            uint8_t cm_check_d[32];
            uint32_t sessionCtr;
            uint8_t *proof_bytes[NUM_ROUNDS];
            if (!onlySigs) {
                for (int i = 0; i < NUM_ROUNDS; i++) {
                    proof_bytes[i] = (uint8_t *)req->proof(i).c_str();
                }
            }
            string challengeStr = req->challenge();
            string ctStr = req->ct();
            string ivStr = req->iv();
            INIT_TIMER;
            START_TIMER;
            server->VerifyProofAndSign(req->id(), proof_bytes, (uint8_t *)req->challenge().c_str(), (uint8_t *)req->ct().c_str(), (uint8_t *)req->iv().c_str(), (uint8_t *)req->tag().c_str(), req->tag().size(), (uint8_t *)req->digest().c_str(), (uint8_t *)req->d().c_str(), req->d().size(), (uint8_t *)req->e().c_str(), req->e().size(), d, &d_len, e, &e_len, cm_check_d, &sessionCtr);
            resp->set_d(d, d_len);
            resp->set_e(e, e_len);
            resp->set_cm_check_d(cm_check_d, 32);
            resp->set_session_ctr(sessionCtr);
            return Status::OK;
        }

        Status SendAuthCheck(ServerContext *context, const AuthCheckRequest *req, AuthCheckResponse *resp) override {
            uint8_t check_d[32];
            uint8_t check_d_open[16];
            unsigned int len;
            server->FinishSign(req->session_ctr(), (uint8_t *)req->cm_check_d().c_str(), check_d, &len, check_d_open);
            resp->set_check_d(check_d, len);
            resp->set_check_d_open(check_d_open, 16);
            return Status::OK;
        }

        Status SendAuthCheck2(ServerContext *context, const AuthCheck2Request *req, AuthCheck2Response *resp) override {
            uint8_t out[32];
            unsigned int out_len;
            server->FinalSign(req->session_ctr(), (uint8_t *)req->check_d().c_str(), req->check_d().size(), (uint8_t *)req->check_d_open().c_str(), out, &out_len);
            resp->set_out(out, out_len);
            return Status::OK;
        }

};

void runServer(string bindAddr, bool onlySigs) {
    LogServer *s = new LogServer(onlySigs);
    LogServiceImpl logService(s, onlySigs);

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
    string bindAddr = LOG_BIND_ADDR; // + string(config[PORT]);

    cout << "going to bind to " << bindAddr << endl;
    bool onlySigs = (argc > 1) && (strcmp(argv[1], "sigs") == 0);
    if (onlySigs) {
        cout << "running WITHOUT proof verification" << endl;
    } else {
        cout << "running with proof verification" << endl;
    }
    runServer(bindAddr, onlySigs);
}
