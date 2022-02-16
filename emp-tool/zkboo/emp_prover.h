#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "prover.h"
#include "view.h"

using namespace emp;

class ZKBooCircExecProver : public CircuitExecution {
    public:
        uint64_t and_ct = 0;
        int wireIdx;
        Prover p;
        CircuitView view;

        ZKBooCircExecProver(int wire);

        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override;

        block xor_gate(const block &a, const block &b) override;

        block not_gate(const block &a) override;

        uint64_t num_and() override;

        block public_label(bool b) override;
};

#endif
