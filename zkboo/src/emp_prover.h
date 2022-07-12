#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include "prover.h"
#include "view.h"

using namespace emp;

static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    *x = *x | (val << bit);
}

template<typename T>
class ZKBooCircExecProver : public CircuitExecution {
    public:
        uint64_t and_ct = 0;
        Prover *p;
        CircuitView *proverViews[3];
        int nextWireNum;
        uint32_t idx[32];

        ZKBooCircExecProver(uint8_t seeds[3][32][16], block *w, int wLen, int numRands) {
            for (int i = 0; i < 3; i++) {
                proverViews[i] = new CircuitView();
            }
            p = new Prover(seeds, numRands);
 
            for (int i = 0; i < wLen; i++) {
                uint32_t shares[3];
                memcpy(shares, (uint8_t *)&w[i], 3 * sizeof(uint32_t));
                uint32_t vals[2];
                proverViews[0]->wires.push_back(shares[0]);
                proverViews[1]->wires.push_back(shares[1]);
                proverViews[2]->wires.push_back(shares[2]);
            }
            nextWireNum = wLen;
        }

        ~ZKBooCircExecProver() {
            //fprintf(stderr, "****** Num ands: %d \n", p->numAnds);
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            and_ct++;
            uint32_t a_shares[3];
            uint32_t b_shares[3];
            uint32_t out_shares[3];
            memcpy(a_shares, (uint8_t *)&a, 3 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 3 * sizeof(uint32_t));
            p->MultShares(a_shares, b_shares, out_shares);
            block out;
            proverViews[0]->wires.push_back(out_shares[0]);
            proverViews[1]->wires.push_back(out_shares[1]);
            proverViews[2]->wires.push_back(out_shares[2]);
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 3 * sizeof(uint32_t));
            //printf("AND (%d %d %d) %d %d -> (%d %d %d) %d\n", a_shares[0], a_shares[1], a_shares[2], a_shares[0] ^ a_shares[1] ^ a_shares[2], b_shares[0] ^ b_shares[1] ^ b_shares[2], out_shares[0], out_shares[1], out_shares[2], out_shares[0] ^ out_shares[1] ^ out_shares[2]);
            return out;
            //return a;
        }

        block xor_gate(const block &a, const block &b) override {
            return a ^ b;
        }

        block not_gate(const block &a) override {
            return a ^ makeBlock(-1, -1);
        }

        uint64_t num_and() override {
            return p->numAnds;
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
