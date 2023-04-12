#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"

//#include "chacha20.c"
#include "common.h"

using namespace std;
using namespace emp;

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#ifdef PREPARSED_CIRCUIT
#if MAX_KEYS == 20
#include "circuits/totp20.h"
#elif MAX_KEYS == 40
#include "circuits/totp40.h"
#elif MAX_KEYS == 60
#include "circuits/totp60.h"
#elif MAX_KEYS == 80
#include "circuits/totp80.h"
#elif MAX_KEYS == 100
#include "circuits/totp100.h"
#endif

static BristolFormat circuit(
#if MAX_KEYS == 20
	circuits_totp20_num_gate,
	circuits_totp20_num_wire,
	circuits_totp20_n1,
	circuits_totp20_n2,
	circuits_totp20_n3,
	circuits_totp20_gate_arr
#elif MAX_KEYS == 40
	circuits_totp40_num_gate,
	circuits_totp40_num_wire,
	circuits_totp40_n1,
	circuits_totp40_n2,
	circuits_totp40_n3,
	circuits_totp40_gate_arr
#elif MAX_KEYS == 60
	circuits_totp60_num_gate,
	circuits_totp60_num_wire,
	circuits_totp60_n1,
	circuits_totp60_n2,
	circuits_totp60_n3,
	circuits_totp60_gate_arr
#elif MAX_KEYS == 80
	circuits_totp80_num_gate,
	circuits_totp80_num_wire,
	circuits_totp80_n1,
	circuits_totp80_n2,
	circuits_totp80_n3,
	circuits_totp80_gate_arr
#elif MAX_KEYS == 100
	circuits_totp100_num_gate,
	circuits_totp100_num_wire,
	circuits_totp100_n1,
	circuits_totp100_n2,
	circuits_totp100_n3,
	circuits_totp100_gate_arr
#endif
);
#else
static BristolFormat circuit("circuits/totp" STR(MAX_KEYS) ".txt");
#endif

static void fill_bits(bool* bool_buf, uint8_t* bytes_buf, int len) {
	for (int i = 0; i < len; i++) {
		for (int j = 0; j < 8; j++) {
			bool_buf[i * 8 + j] = (bytes_buf[i] >> j) & 1;
		}
	}
}

C2PC<NetIO> *do_mpc_offline(int party, NetIO *io) {
	C2PC<NetIO> *twopc = new C2PC<NetIO>(io, party, &circuit);
	io->flush();

	twopc->function_independent();
	io->flush();

	twopc->function_dependent();
	io->flush();
	return twopc;

}

static Output do_mpc_common(int party, bool* input, C2PC<NetIO>* twopc) {
	/*C2PC<NetIO> twopc(io, party, &circuit);
	io->flush();

	twopc.function_independent();
	io->flush();

	twopc.function_dependent();
	io->flush();*/

    auto out = new bool[circuit.n3];
	twopc->online(input, out, true);

    // bits -> bytes
	auto out_bytes = new uint8_t[circuit.n3 / 8];
	for (int i = 0; i < circuit.n3 / 8; i++) {
		out_bytes[i] = 0;
		for (int j = 0; j < 8; j++) {
			out_bytes[i] |= out[i * 8 + j] << j;
		}
	}

	// byte swap
	auto output = *((struct Output*) out_bytes);
	output.otp = __builtin_bswap32(output.otp);

	cout << "[mpc out] otp " << output.otp << "\n";
    print_hex("enc_rpid", (char*) output.enc_rpid, ENC_RPID_LEN);

	delete[] input;
	delete[] out;
	delete[] out_bytes;
	return output;
}

Output do_mpc_client(InputA& in_a, C2PC<NetIO> *twopc) {
    auto input = new bool[circuit.n1 + circuit.n2];
    printf("n1=%d(%d) n2=%d(%d) total=%d(%d) | sizeof=%d\n", circuit.n1, circuit.n1 / 8, circuit.n2, circuit.n2 / 8, circuit.n1 + circuit.n2, (circuit.n1 + circuit.n2) / 8, sizeof(InputA));
    fill_bits(input, (uint8_t*)&in_a, sizeof(in_a));
    //print_bits("mpc in", input, circuit.n1 + circuit.n2);

	//NetIO io(ip.c_str(), port);
	//io.set_nodelay();
    return do_mpc_common(CLIENT, input, twopc);
}
/*
    // decrypt rpid
    uint8_t chacha_block[64];
    chacha20_block((uint32_t*) chacha_block, (uint8_t*) in_a.client_rpid_key, 0, in_a.client_rpid_auth_nonce);
	auto rpid = output->enc_rpid ^ chacha_block[0];
*/
Output do_mpc_server(InputB& in_b, C2PC<NetIO> *twopc) {
    char counter[MSG_LEN] = {0, };
    uint64_t counter_val = 0;
    counter_val = time(NULL) / PERIOD;
    ((uint64_t*)counter)[0] = __bswap_64(counter_val);

    memcpy(in_b.server_time_counter, &counter, sizeof(counter));
    auto input = new bool[circuit.n1 + circuit.n2];
    fill_bits(input + circuit.n1, (uint8_t*)&in_b, sizeof(in_b));
    //print_bits("mpc in", input, circuit.n1 + circuit.n2);

	//NetIO io(nullptr, port);
	//io.set_nodelay();
    return do_mpc_common(SERVER, input, twopc);
}
 
