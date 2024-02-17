#include <fstream>
#include <grpcpp/grpcpp.h>
#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>
#include <thread>

#include "../network/totp.grpc.pb.h"
#include "common.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using namespace std;
using namespace emp;

class TotpServiceImpl : public TotpService::Service {
private:
	ServerState* state;
	vector<SerializedLogEntry> log;
	int mpc_port;
	uint8_t last_enc_rpid[ENC_RPID_LEN] = { 0, };
	EC_POINT* rpid_sign_pk;
    Params params;
	std::thread mpc_server_thread;
	std::thread offline_server_thread;
	C2PC<NetIO> *twopc;
	NetIO *io;
    uint32_t auth_ctr;

public:
	TotpServiceImpl(ServerState* state, int mpc_port, EC_POINT* rpid_sign_pk) : state(state), mpc_port(mpc_port), rpid_sign_pk(rpid_sign_pk) {}

	Status Init(ServerContext* context, const InitRequest* request, InitResponse* response) override {
		params = Params_new(P256);
        //cout << "init\n";
		if (request->rpid_key_commitment().size() != COMMIT_LEN) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "rpid_key_commitment must be 20 bytes");
		}
		if (request->server_key_shares().size() != KEY_LEN * MAX_KEYS) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "server_key_shares must be 2048 bytes");
		}
		if (request->rpid_sign_pk().size() != 65) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "rpid_sign_pk must be 65 bytes");
		}

		//print_hex("reg rpid_key_commitment", request->rpid_key_commitment().data(), COMMIT_LEN);
		memcpy(state->rpid_key_commitment, request->rpid_key_commitment().data(), COMMIT_LEN);
		memcpy(state->server_key_shares, request->server_key_shares().data(), KEY_LEN * MAX_KEYS);
		memcpy(state->rpid_sign_pk, request->rpid_sign_pk().data(), 65);

		vector<uint8_t> pk(request->rpid_sign_pk().begin(), request->rpid_sign_pk().end());
		rpid_sign_pk = load_ecdsa_pk(params, pk);
        auth_ctr = 0;
		write_state();
		return Status::OK;
	}

	Status Register(ServerContext* context, const RegisterRequest* request, RegisterResponse* response) override {
		//cout << "register\n";
		if (request->rp_index() < 0 || request->rp_index() >= MAX_KEYS) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "rp_index must be between 0 and 1023");
		}
		if (request->server_key_share().size() != KEY_LEN) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "key must be 64 bytes");
		}

		auto server_key_share = state->server_key_shares + request->rp_index() * KEY_LEN;
		memcpy(server_key_share, request->server_key_share().data(), KEY_LEN);
		write_state();
		return Status::OK;
	}

	Status StartOffline(ServerContext *context, const StartOfflineRequest *request, StartOfflineResponse *response) override {
		offline_server_thread = std::thread([=]() {
			io = new NetIO(nullptr, mpc_port);
			io->set_nodelay();
			twopc = do_mpc_offline(SERVER, io);
		});
		return Status::OK;
	}

	Status StartAuth(ServerContext* context, const StartAuthRequest* request, StartAuthResponse* response) override {
		//cout << "start auth\n";
		// start mpc server
		mpc_server_thread = std::thread([=]() {
			InputB input;
			// rpid_key_commitment
			memcpy(input.server_rpid_key_commitment, state->rpid_key_commitment, COMMIT_LEN);
			//print_hex("server_rpid_key_commitment", input.server_rpid_key_commitment, COMMIT_LEN);
			// server_key_shares
			memcpy(input.server_key_shares, state->server_key_shares, KEY_LEN * MAX_KEYS);
			// do_mpc_server fills in counter
            memset((uint8_t *) input.server_rpid_auth_nonce, 0, AUTH_NONCE_LEN);
            memcpy((uint8_t *) input.server_rpid_auth_nonce, (uint8_t *)(&auth_ctr), sizeof(auth_ctr));

			//cout << "mpc start\n";
			auto out = do_mpc_server(input, twopc);
			//cout << "mpc end\n";
			memcpy(last_enc_rpid, out.enc_rpid, ENC_RPID_LEN);
		});

		return Status::OK;
	}

	Status FinishAuth(ServerContext* context, const FinishAuthRequest* request, FinishAuthResponse* response) override {
		//cout << "finish auth\n";
		mpc_server_thread.join();
		if (memcmp(last_enc_rpid, request->enc_rpid().data(), ENC_RPID_LEN) != 0) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "enc_rpid does not match");
		}

		// verify ecdsa
		vector<uint8_t> sig(request->signature().begin(), request->signature().end());
		vector<uint8_t> enc_rpid(request->enc_rpid().begin(), request->enc_rpid().end());
        uint8_t verify_bytes[ENC_RPID_LEN + AUTH_NONCE_LEN];
        memcpy(verify_bytes, request->enc_rpid().c_str(), ENC_RPID_LEN);
        memset(verify_bytes + 2, 0, AUTH_NONCE_LEN);
        memcpy(verify_bytes + 2, (uint8_t *)(&auth_ctr), sizeof(auth_ctr));
        vector<uint8_t> verify_bytes_vec(verify_bytes, verify_bytes + ENC_RPID_LEN + AUTH_NONCE_LEN);
		if (!verify_ecdsa(params, rpid_sign_pk, verify_bytes_vec, sig)) {
			return Status(grpc::StatusCode::INVALID_ARGUMENT, "ecdsa signature does not match");
		}

		// add to log
		SerializedLogEntry entry;
		memcpy(entry.enc_rpid, enc_rpid.data(), enc_rpid.size());
        memcpy(entry.rpid_sig, sig.data(), sig.size());
		entry.timestamp = time(nullptr);
		log.push_back(entry);

        auth_ctr++;

		write_state();
		return Status::OK;
	}

	Status GetLog(ServerContext* context, const GetLogRequest* request, GetLogResponse* response) override {
		//cout << "get log\n";
		// fill from log
		for (auto entry : log) {
			auto entry_proto = response->add_entries();
			entry_proto->set_timestamp(entry.timestamp);
			entry_proto->set_enc_rpid(entry.enc_rpid, ENC_RPID_LEN);
			entry_proto->set_rpid_sig(entry.rpid_sig, SIG_LEN);
		}

		return Status::OK;
	}

	void write_state() {
        auto pk = save_ecdsa_pk(params, rpid_sign_pk);
        memcpy(state->rpid_sign_pk, pk.data(), pk.size());

        // write state to data/server.bin
        ofstream file("data/server.bin", ios::out | ios::binary);
        file.write((char*)state, sizeof(*state));
        file.close();
	}

    static TotpServiceImpl* from_state(int mpc_port) {
        // read state from data/server.bin
        ifstream file("data/server.bin", ios::in | ios::binary);
        if (!file.is_open()) {
            return new TotpServiceImpl(new ServerState(), mpc_port, nullptr);
        }

        ServerState* state = new ServerState();
        file.read((char*)state, sizeof(*state));
        file.close();
        
        Params params = Params_new(P256);
		vector<uint8_t> pk(state->rpid_sign_pk, state->rpid_sign_pk + sizeof(state->rpid_sign_pk));
		auto rpid_sign_pk = load_ecdsa_pk(params, pk);
        Params_free(params);
        return new TotpServiceImpl(state, mpc_port, rpid_sign_pk);
    }
};

int main(int argc, char** argv) {
	// port, default = GRPC_PORT
	int port = GRPC_PORT;
	if (argc > 1) {
		port = atoi(argv[1]);
	}

	// mpc port, default = MPC_PORT
	int mpc_port = MPC_PORT;
	if (argc > 2) {
		mpc_port = atoi(argv[2]);
	}

	std::string server_address("0.0.0.0:" + to_string(port));
	auto service = TotpServiceImpl::from_state(mpc_port);

	ServerBuilder builder;
	// Listen on the given address without any authentication mechanism.
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
	// Register "service" as the instance through which we'll communicate with
	// clients. In this case it corresponds to an *synchronous* service.
	builder.RegisterService(service);
	// Finally assemble the server.
	std::unique_ptr<Server> server(builder.BuildAndStart());
	std::cout << "Server listening on " << server_address << std::endl;

	// Wait for the server to shutdown. Note that some other thread must be
	// responsible for shutting down the server for this call to ever return.
	server->Wait();

	return 0;
}
