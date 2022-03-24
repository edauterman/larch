#include <stdlib.h>
#include <stdio.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"

#include "log.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

//using json = nlohmann::json;
using namespace std;

LogServer::LogServer() {
}

class LogServiceImpl final : public Log::Service {
    public:
        LogServer &server;

        LogServiceImpl(LogServer &server) : server(server) {}

        Status SendPublishScores(ServerContext *context, const PublishScoresRequest *req, PublishScoresResponse *resp) override {
            printf("Received publish scores\n");
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
