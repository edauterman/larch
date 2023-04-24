#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include "prover.h"
#include "view.h"
#include "verifier.h"
#include "prover_sys.h"

using namespace emp;

template<typename T>
class ZKBooCircExecVerifier : public CircuitExecution {
    public:
        CircuitView *in_view;
        CircuitView *out_view;
        bool verified;
        int gateNum;
        Verifier *v;
        int nextWireNum;

        ZKBooCircExecVerifier(RandomSource *in_rands[], CircuitView *view, uint32_t *out_w, int wLen, uint32_t *idx) {
            in_view = view;
            out_view = new CircuitView();
            for (int i = 0; i < wLen; i++) {
                out_view->wires.push_back(out_w[i]);
            }
            verified = true;
            gateNum = -1;
            v = new Verifier(in_rands, idx);
            nextWireNum = wLen;
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
            v->MultShares(a_shares, b_shares, out_shares);
            block out;
            out_shares[1] = in_view->wires[nextWireNum];
            out_view->wires.push_back(out_shares[0]);
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
 
            return out;
        }

        block xor_gate(const block &a, const block &b) override {
            return a ^ b;
        }

        block not_gate(const block &a) override {
            return a ^ makeBlock(-1, -1);
        }

        uint64_t num_and() override {
            return 0;
        }

        block public_label(bool b) override {
            if (b == 0) {
                return makeBlock(0,0);
            } else {
                return makeBlock(-1, -1);
            }
        }
};

#endif
