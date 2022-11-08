#include "seal/seal.h"
#include <string>

#include "passwords.h"

using namespace std;
using namespace seal;

// TODO make PwdClient object with public_key and secret_key and num passwords, n

inline string uint64_to_hex_string(uint64_t value)
{
    return util::uint_to_hex_string(&value, size_t(1));
}

SEALContext SetContext() {
    EncryptionParameters params(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(1024);
    SEALContext context(params);
    return context;
}

PwdClient::PwdClient() : context(SetContext()) {}

void PwdClient::KeyGen() {
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
}

Ciphertext *PwdClient::GenEncryptedVector(int idx) {
    Encryptor encryptor(context, public_key);
    Ciphertext *c = new Ciphertext[num_pwds];
    for (int i = 0; i < num_pwds; i++) {
        uint64_t x = i == idx;
        Plaintext x_plain(uint64_to_hex_string(x));
        encryptor.encrypt(x_plain, c[i]);
    }
    return c;
}

string PwdClient::Decrypt(Ciphertext &c) {
    Decryptor decryptor(context, secret_key);
    Plaintext x_dec;
    decryptor.decrypt(c, x_dec);
    return x_dec.to_string();   // TODO to int instead of to string
}

PwdServer::PwdServer(PublicKey &public_key_) : context(SetContext()), public_key(public_key_) {}

Ciphertext PwdServer::Eval(Ciphertext *c, uint64_t *inputs) {
    Evaluator evaluator(context);
    Encryptor encryptor(context, public_key);
    Ciphertext sum;
    Plaintext zero(uint64_to_hex_string(0));
    encryptor.encrypt(zero, sum);
    for (int i = 0; i < num_pwds; i++) {
        Plaintext plain(uint64_to_hex_string(inputs[i]));
        Ciphertext res;
        evaluator.multiply_plain(c[i], plain, res);
        evaluator.add_inplace(sum, res);
    }
    return sum;
}

int main() {

}
