#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include "circuit.h"

using namespace std;
using namespace emp;

void hash_in_circuit(block output[], block input[], int len) {

    Integer ints[len];
    for (int i = 0; i < len; i++) {
        ints[i] = Integer(1,0, PUBLIC);
    }
    Integer ints2[1];
    ints2[0] = Integer(512, 0, PUBLIC);
    uint8_t *ints_raw = (uint8_t *)&(ints2[0]);
    printf("ints_raw: ");
    for (int i = 0; i < len ; i++) {
        printf("%x", ints2[0].bits[i].bit);
    }
    printf("\n");
    uint8_t output_bytes[32];

    block *input2 = new block[512]; //(block *)malloc(512 * sizeof(block));
    block *output2 = new block[256]; //(block *)malloc(256 * sizeof(block));
    memset((uint8_t *)input2, 0, sizeof(block) * 512);
    memset((uint8_t *)output2, 0xa, sizeof(block) * 256);
    printf("input2: ");
    for (int i = 0; i < len; i++) {
        input2[i] = CircuitExecution::circ_exec->public_label(0);
        printf("%x", input2[i]);
    }
    printf("\n");
    //for (int i = 0; i < 512; i++) {
    //    input2[i] = makeBlock(0,0);
    //}
    Integer output_ints = Integer(512, 0, PUBLIC);
    //Integer output_ints = Integer(10, 32, PUBLIC);
    SHA3_256_Calculator sha3_256_calc = SHA3_256_Calculator();
    //sha3_256_calc.sha3_256(&output_ints, ints, len); // WORKS
    memset(input, 0, len * sizeof(block));
    //sha3_256_calc.sha3_256(&output_ints, ints2, 1);
    size_t len2 = 512;
    memset((uint8_t *)output2, 0, sizeof(block) * 256);
    /*printf("output bits!!: ");
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < sizeof(block); j++) {
            printf("%x", ((uint8_t *)&output2[i])[j]);
        }
    }
    printf("\n");
 */
    sha3_256_calc.sha3_256(output, (const block *)input2, len2);
    sha3_256_calc.sha3_256(&output_ints, (const block *)input2, len2);
    //sha3_256_calc.sha3_256(output, input, len);
    output_ints.reveal<uint8_t>(output_bytes, PUBLIC);
    printf("output bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%x", output_bytes[i]);
    }
    printf("\n");

    bool bs[256];
    ProtocolExecution::prot_exec->reveal(bs, PUBLIC, output, 256);
    from_bool(bs, output_bytes, 256);
    printf("output bits: ");
    for (int i = 0; i < 32; i++) {
        printf("%x", output_bytes[i]);
        //cout << bs[i];
        //cout << getLSB(output2[i]);
        //printf("%d", ((uint8_t *)&output2[i])[0] & 1);
        /*for (int j = 0; j < sizeof(block); j++) {
            printf("%x", ((uint8_t *)&output2[i])[j]);
        }*/
    }
    printf("\n");
    printf("\n");
    //sha3_256_calc.sha3_256(output, input, len);

}
