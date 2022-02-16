#include <emp-tool/emp-tool.h>
#include "emp_prover.h"
#include "prover.h"
#include "view.h"

using namespace emp;

/*ZKBooCircExecProver::ZKBooCircExecProver(int wire) {
    wireIdx = wire;
}*/

// each block is a share of 3 wire values

block ZKBooCircExecProver::and_gate(const block &a, const block &b) {
    and_ct++;
    uint64_t out = p.MultShares(a[0], a[1], b[0], b[1]);
    view.wireShares.push_back(out);
    return makeBlock(0, out); 
}

block ZKBooCircExecProver::xor_gate(const block &a, const block &b) {
    uint64_t out = p.AddShares(a[0], b[0]);
    view.wireShares.push_back(out);
    return makeBlock(0, out);
}

block ZKBooCircExecProver::not_gate(const block &a) { 
    if (wireIdx == 0) {
        uint64_t out = p.AddConst(a[0], 1);
        view.wireShares.push_back(out);
        return makeBlock(0, out);
    }
    view.wireShares.push_back(a[0]);
    return a;
}

uint64_t ZKBooCircExecProver::num_and() {
    return and_ct;
}

block ZKBooCircExecProver::public_label(bool b) {
    return makeBlock(0,0);
}
