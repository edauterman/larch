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
#include "../zkboo/utils/timer.h"

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

Token::Token(uint8_t *ct_in, uint8_t *iv_in, uint8_t *sig_in, unsigned int sig_len) {
    memcpy(ct, ct_in, SHA256_DIGEST_LENGTH);
    memcpy(iv, iv_in, 16);
    memset(sig, 0, MAX_ECDSA_SIG_SIZE);
    memcpy(sig, sig_in, sig_len);
}

AuthState::AuthState(BIGNUM *check_d_in, BIGNUM *check_e_in, BIGNUM *out_in) {
    check_d = check_d_in;
    check_e = check_e_in;
    out = out_in;
}

InitState::InitState() {}

LogServer::LogServer(bool onlySigs_in) {
    params = Params_new(P256);
    onlySigs = onlySigs_in;
    //auth_ctr = 0;
};

void LogServer::GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret) {
    uint8_t pt[16];
    uint8_t out[16];
    int len;
    memset(pt, 0, 16);
    memcpy(pt, (uint8_t *)&ctr, sizeof(uint64_t));
    EVP_EncryptUpdate(ctx, out, &len, pt, 16);
    BN_bin2bn(out, len, ret);
    BN_mod(ret, ret, Params_order(params), bn_ctx);
}

void LogServer::GetPreprocessValue(uint64_t ctr, BIGNUM *ret, uint8_t *seed_in) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t iv[16];
    memset(iv, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed_in, iv);
    GetPreprocessValue(ctx, bn_ctx, ctr, ret);
}

void LogServer::GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *alpha, uint8_t *seed_in) {
    uint64_t ctr = i * 4; 
    GetPreprocessValue(ctr, r, seed_in);
    GetPreprocessValue(ctr + 1, a, seed_in);
    GetPreprocessValue(ctr + 2, b, seed_in);
    GetPreprocessValue(ctr + 3, alpha, seed_in);
}

void LogServer::Initialize(const InitRequest *req, uint8_t *pkBuf) {
    InitState *initSt = new InitState();
    memcpy(initSt->enc_key_comm, req->key_comm().c_str(), 32);

    for (int i = 0; i < req->hints_size(); i++) {
        Hint h;
        h.xcoord = BN_bin2bn((uint8_t *)req->hints(i).xcoord().c_str(), req->hints(i).xcoord().size(), NULL);
        h.auth_xcoord = BN_bin2bn((uint8_t *)req->hints(i).auth_xcoord().c_str(), req->hints(i).auth_xcoord().size(), NULL);
        //h.r = BN_bin2bn((uint8_t *)req->hints(i).r().c_str(), req->hints(i).r().size(), NULL);
        h.auth_r = BN_bin2bn((uint8_t *)req->hints(i).auth_r().c_str(), req->hints(i).auth_r().size(), NULL);
        //h.a = BN_bin2bn((uint8_t *)req->hints(i).a().c_str(), req->hints(i).a().size(), NULL);
        //h.b = BN_bin2bn((uint8_t *)req->hints(i).b().c_str(), req->hints(i).b().size(), NULL);
        h.c = BN_bin2bn((uint8_t *)req->hints(i).c().c_str(), req->hints(i).c().size(), NULL);
        h.f = BN_bin2bn((uint8_t *)req->hints(i).f().c_str(), req->hints(i).f().size(), NULL);
        h.g = BN_bin2bn((uint8_t *)req->hints(i).g().c_str(), req->hints(i).g().size(), NULL);
        h.h = BN_bin2bn((uint8_t *)req->hints(i).h().c_str(), req->hints(i).h().size(), NULL);
        //h.alpha = BN_bin2bn((uint8_t *)req->hints(i).alpha().c_str(), req->hints(i).alpha().size(), NULL);
        initSt->hints.push_back(h);
    }
    //printf("done copying in hints\n");
    initSt->auth_pk = EC_POINT_new(Params_group(params));
    memcpy(initSt->log_seed, (uint8_t *)req->log_seed().c_str(), 16);
    EC_POINT_oct2point(Params_group(params), initSt->auth_pk, (uint8_t *)req->auth_pk().c_str(), 33, Params_ctx(params));

    initSt->pk = EC_POINT_new(Params_group(params));
    initSt->sk = BN_new();
    //BN_zero(sk);
    //pk = EC_POINT_dup(Params_gen(params), Params_group(params));
    Params_rand_point_exp(params, initSt->pk, initSt->sk);
    //Params_rand_point_exp(params, pk, sk);
    //printf("chose key\n");
    memset(pkBuf, 0, 33);
    EC_POINT_point2oct(Params_group(params), initSt->pk, POINT_CONVERSION_COMPRESSED, pkBuf, 33, Params_ctx(params));
    initSt->auth_ctr = 0;

    clientMap[req->id()] = initSt;
}

void LogServer::VerifyProofAndSign(uint32_t id, uint8_t *proof_bytes[NUM_ROUNDS], uint8_t *challenge, uint8_t *ct, uint8_t *iv_bytes, uint8_t *auth_sig, unsigned int auth_sig_len, uint8_t *digest, uint8_t *d_in, unsigned int d_in_len, uint8_t *e_in, unsigned int e_in_len, uint8_t *d_out, unsigned int *d_len, uint8_t *e_out, unsigned int *e_len, uint32_t *sessionCtr) {
    Proof proof[NUM_ROUNDS];
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
    BIGNUM *check_d = BN_new();
    BIGNUM *check_e = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *alpha = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    //proof.Deserialize(proof_bytes, numRands);
    
    uint32_t auth_ctr = clientMap[id]->auth_ctr;

    uint64_t low = *((uint64_t *)iv_bytes);
    uint64_t high = *(((uint64_t *)iv_bytes) + 1);
    __m128i iv = makeBlock(low, high);
    memcpy((uint8_t *)&iv, iv_bytes, 16);
           
    // TODO somehow need to check key_comm matches things? and that ct is correctly in the witness?
    // TODO digest is different?????
    /*printf("digest: ");
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
    printf("\n");*/
    bool final_check = true;
    bool check[NUM_ROUNDS];
    thread workers[NUM_ROUNDS];
    if (!onlySigs) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            proof[i].Deserialize(proof_bytes[i], numRands);
            workers[i] = thread(VerifyCtCircuit, &proof[i], iv, m_len, challenge_len, digest, clientMap[id]->enc_key_comm, ct, &check[i]);
            //bool check = VerifyCtCircuit(proof, iv, m_len, challenge_len, digest, enc_key_comm, ct);
        }
        for (int i = 0; i < NUM_ROUNDS; i++) {
            workers[i].join();
            final_check = final_check && check[i];
        }
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

    // TODO make sure that digest lines up with value in serialized proof
    BN_bin2bn(digest, 32, hash_bn);
    BN_mod(hash_bn, hash_bn, Params_order(params), ctx);
    //printf("converted hash to bn\n");
    //printf("message hash bn = %s\n", BN_bn2hex(hash_bn));

    //printf("auth ctr = %d\n", auth_ctr);
    //printf("x_coord = %s\n", BN_bn2hex(hints[auth_ctr].xcoord));
    BN_mod_mul(val, clientMap[id]->hints[auth_ctr].xcoord, clientMap[id]->sk, Params_order(params), ctx);
    //BN_mod_add(val, val, hash_bn, Params_order(params), ctx);
    //printf("got sig mul value\n");
    //printf("r = %s, a = %s, b = %s, c = %s\n", BN_bn2hex(hints[auth_ctr].r), BN_bn2hex(hints[auth_ctr].a), BN_bn2hex(hints[auth_ctr].b), BN_bn2hex(hints[auth_ctr].c));
    //printf("val = %s\n", BN_bn2hex(val));

    BN_mod_mul(auth_hash_bn, hash_bn, alpha, Params_order(params), ctx);
    BN_mod_mul(auth_val, clientMap[id]->hints[auth_ctr].auth_xcoord, clientMap[id]->sk, Params_order(params), ctx);
    BN_mod_add(auth_val, auth_val, auth_hash_bn, Params_order(params), ctx);

    BN_mod_sub(d_log, r, a, Params_order(params), ctx);
    BN_mod_sub(e_log, val, b, Params_order(params), ctx);
    //printf("computed d and e\n");

    BN_mod_sub(auth_d_log, clientMap[id]->hints[auth_ctr].auth_r, clientMap[id]->hints[auth_ctr].f, Params_order(params), ctx);
    BN_mod_sub(auth_e_log, auth_val, clientMap[id]->hints[auth_ctr].g, Params_order(params), ctx);

    BN_mod_add(d, d_log, d_client, Params_order(params),ctx);
    BN_mod_add(e, e_log, e_client, Params_order(params),ctx);
    //printf("d = %s, e = %s\n", BN_bn2hex(d), BN_bn2hex(e));
    //printf("combined d and e\n");

    // de + d[b] + e[a] + [c]
    //BN_mod_mul(out, d, e, Params_order(params), ctx);
    //BN_mod_mul(prod, d, hints[auth_ctr].b, Params_order(params), ctx);
    BN_mod_mul(out, d, b, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, a, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_add(out, out, clientMap[id]->hints[auth_ctr].c, Params_order(params), ctx);
    //printf("computed s\n");
    //printf("share of s = %s\n", BN_bn2hex(out));

    // authenticated value
    // de.\alpha + d[g] + e[f] + [h]
    BN_mod_mul(auth_out, d, e, Params_order(params), ctx);
    BN_mod_mul(auth_out, auth_out, alpha, Params_order(params), ctx);
    BN_mod_mul(prod, d, clientMap[id]->hints[auth_ctr].g, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, clientMap[id]->hints[auth_ctr].f, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, clientMap[id]->hints[auth_ctr].h, Params_order(params), ctx);

    BN_bn2bin(d_log, d_out);
    *d_len = BN_num_bytes(d_log);

    BN_bn2bin(e_log, e_out);
    *e_len = BN_num_bytes(e_log);

    //BN_bn2bin(out, sig_out);
    //*sig_len = BN_num_bytes(out);

    *sessionCtr = rand();
    BN_mod_mul(check_d, alpha, d, Params_order(params), ctx);
    BN_mod_sub(check_d, auth_d_log, check_d, Params_order(params), ctx);
    BN_mod_mul(check_e, alpha, e, Params_order(params), ctx);
    BN_mod_sub(check_e, auth_e_log, check_e, Params_order(params), ctx);
    AuthState *state = new AuthState(check_d, check_e, out);
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
        //EC_KEY_set_group(key, Params_group(params));
        EC_KEY_set_public_key(key, clientMap[id]->auth_pk);
        EVP_PKEY_assign_EC_KEY(pkey, key);
        EVP_VerifyInit(mdctx, EVP_sha256());
        EVP_VerifyUpdate(mdctx, auth_input, 48);
        int ver = EVP_VerifyFinal(mdctx, auth_sig, auth_sig_len, pkey);
        //printf("sig ver result = %d\n", ver);
        /*if (ECDSA_verify(0, auth_input, 48, auth_sig, auth_sig_len, key) != 1) {
            printf("SIG VERIFICATION FAILED\n");
        }*/
    }
};

void LogServer::FinishSign(uint32_t sessionCtr, uint8_t *check_d_buf, unsigned int check_d_len, uint8_t *check_e_buf, unsigned int check_e_len, uint8_t *out, unsigned int *out_len) {
    BIGNUM *check_d_client = BN_new();
    BIGNUM *check_e_client = BN_new();
    BIGNUM *sum = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn(check_d_buf, check_d_len, check_d_client);
    BN_bin2bn(check_e_buf, check_e_len, check_e_client);

    BN_mod_add(sum, check_d_client, saveMap[sessionCtr]->check_d, Params_order(params), ctx);
    if (!BN_is_zero(sum)) {
        fprintf(stderr, "ERROR: MAC tag for d doesn't verify %s %s -> %s\n", BN_bn2hex(check_d_client), BN_bn2hex(saveMap[sessionCtr]->check_d), BN_bn2hex(sum));
        *out_len = 0;
        return;
    }
    BN_mod_add(sum, check_e_client, saveMap[sessionCtr]->check_e, Params_order(params), ctx);
    if (!BN_is_zero(sum)) {
        fprintf(stderr, "ERROR: MAC tag for e doesn't verify %s %s -> %s\n", BN_bn2hex(check_e_client), BN_bn2hex(saveMap[sessionCtr]->check_e), BN_bn2hex(sum));
        *out_len = 0;
        return;
    }

    BN_bn2bin(saveMap[sessionCtr]->out, out);
    *out_len = BN_num_bytes(saveMap[sessionCtr]->out);
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
            uint32_t sessionCtr;
            uint8_t *proof_bytes[NUM_ROUNDS];
            if (!onlySigs) {
                for (int i = 0; i < NUM_ROUNDS; i++) {
                    proof_bytes[i] = (uint8_t *)req->proof(i).c_str();
                }
            }
            //string proofStr = req->proof();
            string challengeStr = req->challenge();
            string ctStr = req->ct();
            string ivStr = req->iv();
            INIT_TIMER;
            START_TIMER;
            //server->VerifyProofAndSign(req->id(), proof_bytes, (uint8_t *)req->challenge().c_str(), (uint8_t *)req->ct().c_str(), (uint8_t *)req->iv().c_str(), (uint8_t *)req->tag().c_str(), req->tag().size(), (uint8_t *)req->digest().c_str(), (uint8_t *)req->d().c_str(), req->d().size(), (uint8_t *)req->e().c_str(), req->e().size(), d, &d_len, e, &e_len, prod, &prod_len);
            server->VerifyProofAndSign(req->id(), proof_bytes, (uint8_t *)req->challenge().c_str(), (uint8_t *)req->ct().c_str(), (uint8_t *)req->iv().c_str(), (uint8_t *)req->tag().c_str(), req->tag().size(), (uint8_t *)req->digest().c_str(), (uint8_t *)req->d().c_str(), req->d().size(), (uint8_t *)req->e().c_str(), req->e().size(), d, &d_len, e, &e_len, &sessionCtr);
            resp->set_d(d, d_len);
            resp->set_e(e, e_len);
            resp->set_session_ctr(sessionCtr);
            //resp->set_prod(prod, prod_len);
            //printf("Sending auth response\n");
            //STOP_TIMER("verifier");
            return Status::OK;
        }

        Status SendAuthCheck(ServerContext *context, const AuthCheckRequest *req, AuthCheckResponse *resp) override {
            uint8_t out[32];
            unsigned int out_len;
            server->FinishSign(req->session_ctr(), (uint8_t *)req->check_d().c_str(), req->check_d().size(), (uint8_t *)req->check_e().c_str(), req->check_e().size(), out, &out_len);
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
    /*ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;*/

    string bindAddr = "0.0.0.0:12345"; // + string(config[PORT]);

    cout << "going to bind to " << bindAddr << endl;
    bool onlySigs = (argc > 1) && (strcmp(argv[1], "sigs") == 0);
    if (onlySigs) {
        cout << "running WITHOUT proof verification" << endl;
    } else {
        cout << "running with proof verification" << endl;
    }
    runServer(bindAddr, onlySigs);
    cout << "after run server?" << endl;

	//printf("Hello world\n");
}
