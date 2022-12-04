#ifndef _PW_CLIENT_H_
#define _PW_CLIENT_H_

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>
#include <map>

#include "../../crypto/src/params.h"
#include "../../crypto/src/pw.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"

using namespace std;

class PwClient {
    public:
        PwClient(bool startConn=true);
        void Initialize();
        void Register(string id, EC_POINT *pw);
        EC_POINT *Authenticate(string id);

    private:
        PasswordClient *c;
        string logAddr;
        unique_ptr<Log::Stub> stub;
        map<string, int> orderMap;
        int ctr;
};

#endif
