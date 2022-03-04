#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include "circuit.h"

using namespace std;
using namespace emp;

void hash_in_circuit(block output[], block input[], int len) {

    SHA3_256_Calculator sha3_256_calc = SHA3_256_Calculator();
    printf("about to do calc\n");
    sha3_256_calc.sha3_256(output, (const block *)input, len);
    printf("just finished calc\n");
    //sha3_256_calc.sha3_256(output, input, len);

    /*bool bs[256];
    for (int i = 0; i < 256; i++) {
        bs[i] = getLSB(output[i]);
    }
    //ProtocolExecution::prot_exec->reveal(bs, PUBLIC, output, 256);
    from_bool(bs, output_bytes, 256);
    printf("output bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%x", output_bytes[i]);
    }
    printf("\n");*/
    //sha3_256_calc.sha3_256(output, input, len);

}
