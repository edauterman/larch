#include "client.hpp"

using namespace std;


// Run after setup and making some authentications
int main(int argc, char** argv) {
    // arg 1 = server ip
    string server_ip(argv[1]);

    // connect grpc
    auto channel = grpc::CreateChannel(server_ip + ":" + to_string(GRPC_PORT), grpc::InsecureChannelCredentials());
    Client client(new ClientState(), channel, server_ip, nullptr);

    client.from_state();
    cout << "print log\n";
    client.print_log();

	return 0;
}
