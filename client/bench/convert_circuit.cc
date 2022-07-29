#include "emp-tool/emp-tool.h"
#include "../../config.h"
#include <cstring>
#include <string>

using namespace emp;
using namespace std;

int main() {
    BristolFormat bf((string(PROJ_DIR) + string("/zkboo/circuit_files/sha-256-multiblock-aligned.txt")).c_str());
    bf.to_file(PROJ_DIR "/zkboo/circuit_files/sha-256-multiblock-aligned.cpp", "empcircuit_sha256_multiblock_aligned");

    /*
    BristolFashion bf2("emp-tool/emp-tool/circuits/files/bristol_fashion/aes_128.txt");
    bf2.to_file("emp-tool/emp-tool/circuits/files/bristol_fashion/aes_128.cpp", "emp_tool_circuits_files_bristol_fashion_aes_128");
    */

    return 0;
}
