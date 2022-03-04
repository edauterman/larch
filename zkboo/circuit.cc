#include <emp-tool/emp-tool.h>
#include <emp-tool/circuits/sha3_256.h>
#include "circuit.h"

using namespace std;
using namespace emp;

void hash_in_circuit(block output[], block input[], int len) {

    SHA3_256_Calculator sha3_256_calc = SHA3_256_Calculator();
    sha3_256_calc.sha3_256(output, input, len);

}
