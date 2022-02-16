#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include "prover.h"
#include "view.h"

using namespace emp;

template<typename T>

class ZKBooCircExecProver : public CircuitExecution {
    public:
        uint64_t and_ct = 0;
        int wireIdx;
        Prover p;
        T *io;
        CircuitView view;

        ZKBooCircExecProver(T *io_in, int wire) {
            printf("constructor\n");
            io = io_in;
            wireIdx = wire;
        }

        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            and_ct++;
            printf("and gate\n");
            uint64_t out = p.MultShares(a[0], a[1], b[0], b[1]);
            view.wireShares.push_back(out);
            return makeBlock(0, out); 
        }

        block xor_gate(const block &a, const block &b) override {
            printf("xor gate\n");
            uint64_t out = p.AddShares(a[0], b[0]);
            view.wireShares.push_back(out);
            return makeBlock(0, out);
        }

        block not_gate(const block &a) override {
            printf("not\n");
            if (wireIdx == 0) {
                uint64_t out = p.AddConst(a[0], 1); 
                view.wireShares.push_back(out);
                return makeBlock(0, out);
            }   
            view.wireShares.push_back(a[0]);
            return a;
        }

        uint64_t num_and() override {
            return and_ct;
        }

        block public_label(bool b) override {
            printf("label\n");
            return makeBlock(0,0);
        }
};

#endif
