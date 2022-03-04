#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include "circuit.h"

using namespace std;
using namespace emp;

void hash_in_circuit(block output[], block input[], int len) {

    uint8_t output_bytes[32];

    block *input2 = new block[512]; //(block *)malloc(512 * sizeof(block));
    memset((uint8_t *)input2, 0, sizeof(block) * 512);
    printf("input2: ");
    for (int i = 0; i < 512; i++) {
    //for (int i = 0; i < len; i++) {
        input2[i] = CircuitExecution::circ_exec->public_label(0);
    }
    printf("\n");
    SHA3_256_Calculator sha3_256_calc = SHA3_256_Calculator();
    sha3_256_calc.sha3_256(output, (const block *)input2, 512);
    //sha3_256_calc.sha3_256(output, input, len);

    bool bs[256];
    ProtocolExecution::prot_exec->reveal(bs, PUBLIC, output, 256);
    from_bool(bs, output_bytes, 256);
    printf("output bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%x", output_bytes[i]);
    }
    printf("\n");
    //sha3_256_calc.sha3_256(output, input, len);

}
