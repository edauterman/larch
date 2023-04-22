#include <stdio.h>
#include <chrono>
#include <thread>
#include <iostream>
#include <fstream>
#include "client.hpp"

using namespace std;
using namespace std::this_thread;
using namespace std::chrono;

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

double getAverage(vector<double> &v) {
        return accumulate( v.begin(), v.end(), 0.0/ v.size());
}


void runBench(string server_ip, int rpid, double *offlineMB, double *onlineMB, double *recvMB, double *offlineMS, double *onlineMS) {
        auto channel = grpc::CreateChannel(server_ip + ":" + to_string(GRPC_PORT), grpc::InsecureChannelCredentials());
        Client client(new ClientState(), channel, server_ip, nullptr);

        client.init();

        unsigned long int recv1, recv2, recv3, trans1, trans2, trans3;
        read_network(&recv1, &trans1);
        auto t1 = std::chrono::high_resolution_clock::now();
        client.offline();
        auto t2 = std::chrono::high_resolution_clock::now();
        sleep_for(seconds(1));
        read_network(&recv2, &trans2);
        auto t3 = std::chrono::high_resolution_clock::now();
        auto otp = client.auth(rpid);
        auto t4 = std::chrono::high_resolution_clock::now();
        read_network(&recv3, &trans3);
        unsigned long int offline_comm, online_comm, in_comm;
        offline_comm = double(trans2 - trans1 + recv2 - recv1);
        online_comm = double(trans3 - trans2 + recv3 - recv2);
        in_comm = double(recv3 - recv1);
        *onlineMB = online_comm / (1048576.0);
        *offlineMB = offline_comm / (1048576.0);
        *recvMB = in_comm / (1048576.0);
        *offlineMS = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        *onlineMS = std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();
        cout << "Offline comm = " << *offlineMB << endl;
        cout << "Online comm = " << *onlineMB << endl;
        cout << "Received comm = " << *recvMB << endl;
        cout << "Offline ms = " << *offlineMS << endl;
        cout << "Online ms = " << *onlineMS << endl;
        cout << "otp = " << otp << "\n";

}

int main(int argc, char** argv) {
        // arg 1 = server ip
        string server_ip(argv[1]);
        // arg 2 = rpid
        int rpid = stoi(argv[2]);
        // arg 3 = out_file
        string out_file(argv[3]);
        vector<double> offlineMBs;
        vector<double> onlineMBs;
        vector<double> recvMBs;
        vector<double> offlinetimes;
        vector<double> onlinetimes;

        for (int i = 0; i < 1; i++) {
                double offlineMB, onlineMB, recvMB, offlineMS, onlineMS;
                runBench(server_ip, rpid, &offlineMB, &onlineMB, &recvMB, &offlineMS, &onlineMS);
                offlineMBs.push_back(offlineMB);
                onlineMBs.push_back(onlineMB);
                recvMBs.push_back(recvMB);
                offlinetimes.push_back(offlineMS);
                onlinetimes.push_back(onlineMS);
                //getchar();
        }
        cout << "offline MB = " << getAverage(offlineMBs) << endl;
        cout << "online MB = " << getAverage(onlineMBs) << endl;
        cout << "received MB = " << getAverage(recvMBs) << endl;
        cout << "offline time (ms) = " << getAverage(offlinetimes) << endl;
        cout << "online time (ms) = " << getAverage(onlinetimes) << endl;
        
        ofstream f;
        f.open(out_file);
        f << getAverage(offlineMBs) << endl;
        f << getAverage(onlineMBs) << endl;
        f << getAverage(recvMBs) << endl;
        f << getAverage(offlinetimes) << endl;
        f << getAverage(onlinetimes) << endl;
        f.close();
        return 0;
}

