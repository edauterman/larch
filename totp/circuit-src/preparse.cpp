#include "emp-tool/emp-tool.h"

#include <inttypes.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>

using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    string base_name(argv[1]);
    string txt_name = base_name + ".txt";
    string h_name = base_name + ".h";
    // replace / with _
    string circ_name = base_name.replace(base_name.find("/"), 1, "_");
    cout << circ_name << endl;

	BristolFormat bf(txt_name.c_str());
	bf.to_file(h_name.c_str(), circ_name.c_str());
    return 0;
}
