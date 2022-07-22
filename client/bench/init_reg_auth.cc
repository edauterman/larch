#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "../src/client.h"
#include "../../zkboo/utils/timer.h"

int main(int argc, char *argv[]) {
    Client *c = new Client();
    //c->ReadFromStorage();

    std::cout << "init\n";
    c->Initialize();
    std::cout << "init done\n";

    std::cout << "write\n";
    c->WriteToStorage();
    std::cout << "write done\n";

    std::cout << "reg\n";
    uint8_t app_id[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    uint8_t challenge[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    uint8_t key_handle_out[32];
    uint8_t cert_sig_out[MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
    P256_POINT pk_out;
    auto ret = c->Register(app_id, challenge, key_handle_out, &pk_out, cert_sig_out);
    std::cout << "reg done: " << ret << "\n";

    std::cout << "write\n";
    c->WriteToStorage();
    std::cout << "write done\n";

    std::cout << "auth\n";
    INIT_TIMER;
    START_TIMER;
    uint8_t flags_out;
    uint32_t ctr_out;
    uint8_t sig_out[MAX_ECDSA_SIG_SIZE];
    ret = c->Authenticate(app_id, 32, challenge, key_handle_out, &flags_out, &ctr_out, sig_out);
    STOP_TIMER("auth");
    std::cout << "auth done: " << ret << "\n";

    std::cout << "write\n";
    c->WriteToStorage();
    std::cout << "write done\n";

    
    return 0;
}
