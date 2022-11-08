#ifndef _PASSWORDS_H_
#define _PASSWORDS_H_

#include "seal/seal.h"
#include <string>

using namespace std;
using namespace seal;

class PwdClient {
    public:
        PwdClient();
        PublicKey KeyGen();
        Ciphertext *GenEncryptedVector(int idx);
        string Decrypt(Ciphertext &c);
        int GetNumPwds();
    private:
        SecretKey secret_key;
        PublicKey public_key;
        SEALContext context;
        int num_pwds = 10;
};

class PwdServer {
    public:
        PwdServer(PublicKey &public_key_);
        Ciphertext Eval(Ciphertext *c, uint64_t *inputs);
    private:
        PublicKey public_key;
        SEALContext context;
        int num_pwds = 10;
};

#endif
