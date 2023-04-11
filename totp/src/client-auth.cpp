#include <stdio.h>
#include "client.hpp"

using namespace std;

void read_network(unsigned long int *r_bytes, unsigned long int *t_bytes) {
    FILE *fp = fopen("/proc/net/dev", "r");
    char buf[200], ifname[20];
    unsigned long int r_packets, t_packets;

    // skip first two lines
    for (int i = 0; i < 2; i++) {
        fgets(buf, 200, fp);
    }

    while (fgets(buf, 200, fp)) {
        sscanf(buf, "%[^:]: %lu %lu %*lu %*lu %*lu %*lu %*lu %*lu %lu %lu",
               ifname, r_bytes, &r_packets, t_bytes, &t_packets);
        printf("%s: rbytes: %lu rpackets: %lu tbytes: %lu tpackets: %lu\n",
               ifname, *r_bytes, r_packets, *t_bytes, t_packets);
    }

    fclose(fp);
}

int main(int argc, char** argv) {
    // arg 1 = server ip
    string server_ip(argv[1]);

	// arg 2 = rpid
	int rpid = stoi(argv[2]);

    auto channel = grpc::CreateChannel(server_ip + ":" + to_string(GRPC_PORT), grpc::InsecureChannelCredentials());
	auto client = Client::from_state(channel, server_ip);

	unsigned long int recv1, recv2, recv3, trans1, trans2, trans3;
	read_network(&recv1, &trans1);
	client->offline();
	read_network(&recv2, &trans2);
	auto otp = client->auth(rpid);
	read_network(&recv3, &trans3);
	unsigned long int offline_comm, online_comm;
	offline_comm = double(trans2 - trans1 + recv2 - recv1);
	online_comm = double(trans3 - trans2 + recv3 - recv2);
	double onlineMB = online_comm / (1 << 20);
	double offlineMB = offline_comm / (1 << 20);
	cout << "Offline raw = " << offline_comm << endl;
	cout << "Offline comm = " << offlineMB << endl;
	cout << "Online comm = " << onlineMB << endl;
	cout << "otp = " << otp << "\n";

	return 0;
}
