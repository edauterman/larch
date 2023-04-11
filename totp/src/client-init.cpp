#include "client.hpp"

using namespace std;

int main(int argc, char** argv) {
    // arg 1 = server ip
    string server_ip(argv[1]);

    // connect grpc
    auto channel = grpc::CreateChannel(server_ip + ":" + to_string(GRPC_PORT), grpc::InsecureChannelCredentials());
    Client client(new ClientState(), channel, server_ip, nullptr);

    // init
    cout << "init\n";
    client.init();

    // other args = b32 keys
    for (int i = 2; i < argc; i++) {
        // format: <idx>:<b32>
        string arg(argv[i]);
        int idx = arg.find(':');
        int key_idx = stoi(arg.substr(0, idx));
        string b32 = arg.substr(idx + 1);
        cout << "register key " << key_idx << " = " << b32 << "\n";
        client.register_totp_key(key_idx, b32);
    }

    cout << "write state\n";
    client.write_state();
	return 0;
}
