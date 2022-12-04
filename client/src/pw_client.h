#ifndef _PW_CLIENT_H_
#define _PW_CLIENT_H_

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <grpcpp/grpcpp.h>

#include "../../crypto/src/params.h"
#include "../../crypto/src/pw.h"
#include "../../network/log.grpc.pb.h"
#include "../../network/log.pb.h"

class PwClient {
    public:
        PwClient(bool startConn=true);
        void Initialize();
        //Register(string id, EC_POINT *pw);
        //Authentication(string id, EC_POINT *pw_out);

    private:
        Params params;
        PasswordClient *c;
        string logAddr;
        unique_ptr<Log::Stub> stub;
};

#endif
