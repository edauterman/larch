#pragma once

#include <vector>
#include <string>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <memory>
#include <string.h>
#include <fstream>
#include <grpcpp/grpcpp.h>

#include "../network/totp.grpc.pb.h"
#include "common.h"
extern "C" {
#include "base32.h"
}

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using namespace std;

vector<uint8_t> decode_b32(const string& input) {
    vector<uint8_t> out((input.size() * 8 + 4) / 5);
    auto size = base32_decode((uint8_t*) input.c_str(), out.data());
    out.resize(size);
    return out;
}

static vector<uint8_t> normalize_key(vector<uint8_t> raw) {
    vector<uint8_t> out(BLOCK_SIZE);
    // too big: hash it with sha1
    if (raw.size() > BLOCK_SIZE) {
        SHA1(raw.data(), raw.size(), out.data());
    } else {
        // too small: right-pad with zeros
        // just right: do nothing
        memcpy(out.data(), raw.data(), raw.size());
    }
    return out;
}

class Client {
private:
    ClientState* state;
    unique_ptr<TotpService::Stub> stub;
    string server_ip;
    BIGNUM* rpid_sign_sk;
    C2PC<NetIO> *twopc;
    NetIO *io;
    Params params;

public:
    Client(ClientState* state, shared_ptr<Channel> channel, string server_ip, BIGNUM* rpid_sign_sk) : state(state), stub(TotpService::NewStub(channel)), server_ip(server_ip), rpid_sign_sk(rpid_sign_sk) {
        params = Params_new(P256);
    }

    void init() {
        // generate rpid key
        RAND_bytes(state->rpid_key, 32);

        // generate rpid commit nonce
        RAND_bytes(state->rpid_commit_nonce, COMMIT_NONCE_LEN);

        // generate keybag xor keys
        RAND_bytes(state->client_key_shares, KEY_LEN * MAX_KEYS);

        // generate rpid signing key
        rpid_sign_sk = gen_ecdsa(params);
        auto pk = derive_ecdsa_pub(params, rpid_sign_sk);

        // compute commitment = SHA256(rpid_key + rpid_commit_nonce)
        vector<uint8_t> commitment(COMMIT_LEN);
        vector<uint8_t> commit_buf(32 + COMMIT_NONCE_LEN);
        memcpy(commit_buf.data(), state->rpid_key, 32);
        memcpy(commit_buf.data() + 32, state->rpid_commit_nonce, COMMIT_NONCE_LEN);
        SHA256(commit_buf.data(), 48, commitment.data());

        // send to server
        ClientContext context;
        InitRequest req;
        InitResponse resp;
		//print_hex("reg commitment", (char*)commitment.data(), commitment.size());
		//print_hex("reg rpid_key", (char*)state->rpid_key, 32);
		//print_hex("reg rpid_commit_nonce", (char*)state->rpid_commit_nonce, COMMIT_NONCE_LEN);
        // rpid_key_commitment
        req.set_rpid_key_commitment(commitment.data(), commitment.size());
        // server_key_shares = keybag_otp_keys (in case of init, XOR 0 = no change)
        req.set_server_key_shares(state->client_key_shares, KEY_LEN * MAX_KEYS);
        req.set_rpid_sign_pk(pk.data(), pk.size());
        auto status = stub->Init(&context, req, &resp);
        if (!status.ok()) {
            throw runtime_error("init failed: " + status.error_message());
        }

        state->auth_ctr = 0;
    }

    void register_totp_key(int rp_index, string secret_b32) {
        // decode b32
        auto secret = decode_b32(secret_b32);
        // normalize
        secret = normalize_key(secret);
        //print_hex("secret", (char*)secret.data(), secret.size());

        // generate new client key share for this key
        auto client_key_share = state->client_key_shares + rp_index * KEY_LEN;
        RAND_bytes(client_key_share, KEY_LEN);

        // compute server key share for this key
        vector<uint8_t> server_key_share(KEY_LEN);
        for (int i = 0; i < KEY_LEN; i++) {
            server_key_share[i] = secret[i] ^ client_key_share[i];
        }

        // send to server
        ClientContext context;
        RegisterRequest req;
        RegisterResponse resp;
        // rp_index
        req.set_rp_index(rp_index);
        // server_key_share
        req.set_server_key_share(server_key_share.data(), server_key_share.size());
        auto status = stub->Register(&context, req, &resp);
        if (!status.ok()) {
            throw runtime_error("register failed: " + status.error_message());
        }
    }

    void offline() {
	ClientContext context;
	StartOfflineRequest req;
	StartOfflineResponse resp;
	auto status = stub->StartOffline(&context, req, &resp);
	if (!status.ok()) {
		throw runtime_error("start offline failed: " + status.error_message());
	}
	io = new NetIO(server_ip.c_str(), MPC_PORT);
	io->set_nodelay();
	twopc = do_mpc_offline(CLIENT, io);
    }

    unsigned int auth(int rp_index) {
        // tell server to start mpc
        ClientContext context;
        StartAuthRequest req;
        StartAuthResponse resp;
        auto status = stub->StartAuth(&context, req, &resp);
        if (!status.ok()) {
            throw runtime_error("start auth failed: " + status.error_message());
        }

        // start mpc on our side
        InputA input;
        input.rp_index = rp_index;
        memcpy(input.client_key_share, state->client_key_shares + rp_index * KEY_LEN, KEY_LEN);
        memcpy(input.client_rpid_key, state->rpid_key, 32);
        memcpy(input.client_rpid_commit_nonce, state->rpid_commit_nonce, COMMIT_NONCE_LEN);
	//print_hex("auth rpid_key", (char*)input.client_rpid_key, 32);
        //print_hex("auth rpid_commit_nonce", (char*)input.client_rpid_commit_nonce, COMMIT_NONCE_LEN);

        // compute commitment = HMAC-SHA1(rpid_key, rpid_commit_nonce)
        vector<uint8_t> commitment(COMMIT_LEN);
        vector<uint8_t> commit_buf(32 + COMMIT_NONCE_LEN);
        memcpy(commit_buf.data(), state->rpid_key, 32);
        memcpy(commit_buf.data() + 32, state->rpid_commit_nonce, COMMIT_NONCE_LEN);
        SHA256(commit_buf.data(), 48, commitment.data());
        //print_hex("auth commitment", (char*)commitment.data(), commitment.size());

        memset((uint8_t *) input.client_rpid_auth_nonce, 0, AUTH_NONCE_LEN);
        memcpy((uint8_t *) input.client_rpid_auth_nonce, (uint8_t *)(&state->auth_ctr), sizeof(state->auth_ctr));
        state->auth_ctr++;

        //RAND_bytes((uint8_t*) input.client_rpid_auth_nonce, AUTH_NONCE_LEN);
        auto out = do_mpc_client(input, twopc);

        // sign enc_rpid with ECDSA
        vector<uint8_t> enc_rpid(out.enc_rpid, out.enc_rpid + ENC_RPID_LEN);
        uint8_t verify_bytes[ENC_RPID_LEN + AUTH_NONCE_LEN];
        memcpy(verify_bytes, enc_rpid, ENC_RPID_LEN);
        memset(verify_bytes + 2, 0, AUTH_NONCE_LEN);
        memcpy(verify_bytes + 2, (uint8_t *)(&auth_ctr), sizeof(auth_ctr);
        vector<uint8_t> verify_bytes_vec(verify_bytes.begin(), verify_bytes.end());
        auto sig = sign_ecdsa(params, rpid_sign_sk, verify_bytes_vec);

        // send to server
        ClientContext context2;
        FinishAuthRequest req2;
        FinishAuthResponse resp2;
        req2.set_enc_rpid(enc_rpid.data(), enc_rpid.size());
        req2.set_signature(sig.data(), sig.size());
        auto status2 = stub->FinishAuth(&context2, req2, &resp2);
        if (!status2.ok()) {
            throw runtime_error("finish auth failed: " + status2.error_message());
        }

        return out.otp;
    }

    void write_state() {
        auto sk = save_ecdsa_sk(rpid_sign_sk);
        memcpy(state->rpid_sign_sk, sk.data(), sk.size());

        // write state to data/client.bin
        ofstream file("data/client.bin", ios::out | ios::binary);
        file.write((char*)state, sizeof(*state));
        file.close();
    }

    void print_log() {
        ClientContext ctx;
        GetLogRequest req;
        GetLogResponse resp;

        auto status = stub->GetLog(&ctx, req, &resp);
        if (!status.ok()) {
            throw runtime_error("get log failed: " + status.error_message());
        }
        
        auto pk = derive_ecdsa_pub(params, rpid_sign_sk);

        for (uint32_t i = 0 ; i < resp.entries.size(); i++) {
            // Verify signature
            uint8_t verify_bytes[ENC_RPID_LEN + AUTH_NONCE_LEN];
            memcpy(verify_bytes, resp.entries(i).enc_rpid(), ENC_RPID_LEN);
            memset(verify_bytes + 2, 0, AUTH_NONCE_LEN);
            memcpy(verify_bytes + 2, (uint8_t *)(&auth_ctr), sizeof(auth_ctr);
            vector<uint8_t> verify_bytes_vec(verify_bytes.begin(), verify_bytes.end());
            
            if (!verify_ecdsa(params, pk, verify_bytes_vec, resp.entries(i).rpid_sig())) {
                printf("signature verification FAILED\n");
            }
            // Decrypt RPID
            uint8_t chacha_block[64];
            uint8_t auth_nonce[12];
            memset((uint8_t *) auth_nonce, 0, AUTH_NONCE_LEN);
            memcpy((uint8_t *) auth_nonce, (uint8_t *)(&i), sizeof(uint32_t));
 
            memcpy(chacha_block, resp.entries(i).enc_rpid(), 64);
            chacha20_block((uint32_t*) chacha_block, (uint8_t*) rpid_key, 0, auth_nonce);
            auto rpid = resp.entries(i).enc_rpid() ^ chacha_block[0];
            cout << "RPID = " << rpid << endl;
        }

    }

    static Client* from_state(shared_ptr<Channel> channel, string server_ip) {
        // read state from data/client.bin
        ifstream file("data/client.bin", ios::in | ios::binary);
        if (!file.is_open()) {
            return new Client(new ClientState(), channel, server_ip, nullptr);
        }

        ClientState* state = new ClientState();
        file.read((char*)state, sizeof(*state));
        file.close();

        vector<uint8_t> sk(state->rpid_sign_sk, state->rpid_sign_sk + sizeof(state->rpid_sign_sk));
        auto rpid_sign_sk = load_ecdsa_sk(sk);
        return new Client(state, channel, server_ip, rpid_sign_sk);
    }
};
