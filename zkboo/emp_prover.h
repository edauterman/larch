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
        //int wireIdx;
        Prover *p;
        CircuitView *view[3];

        ZKBooCircExecProver(uint8_t *seeds[]) {
            printf("constructor\n");
            for (int i = 0; i < 3; i++) {
                view[i] = new CircuitView();
            }
            p = new Prover(seeds);
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            and_ct++;
            //printf("and gate\n");
            uint32_t a_shares[3];
            uint32_t b_shares[3];
            uint32_t out_shares[3];
            memcpy(a_shares, (uint8_t *)&a, 3 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 3 * sizeof(uint32_t));
            p->MultShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 3 * sizeof(uint32_t));
            for (int i = 0; i < 3; i++) {
                view[i]->wireShares.push_back(out_shares[i]);
            }
            //printf("AND %d %d -> %d\n", (a_shares[0] + a_shares[1] + a_shares[2]) % 2, (b_shares[0] + b_shares[1] + b_shares[2]) % 2, (out_shares[0] + out_shares[1] + out_shares[2]) % 2);
            return out;
            //return a;
        }

        block xor_gate(const block &a, const block &b) override {
            //printf("xor gate\n");
            uint32_t a_shares[3];
            uint32_t b_shares[3];
            uint32_t out_shares[3];
            memcpy(a_shares, (uint8_t *)&a, 3 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 3 * sizeof(uint32_t));
            p->AddShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 3 * sizeof(uint32_t));
            for (int i = 0; i < 3; i++) {
                view[i]->wireShares.push_back(out_shares[i]);
            }
            //printf("XOR %d %d -> %d\n", (a_shares[0] + a_shares[1] + a_shares[2]) % 2, (b_shares[0] + b_shares[1] + b_shares[2]) % 2, (out_shares[0] + out_shares[1] + out_shares[2]) % 2);
            return out;
        }

        block not_gate(const block &a) override {
            //printf("not\n");
            uint32_t a_shares[3];
            uint32_t b_shares[3];
            uint32_t out_shares[3];
            memcpy(a_shares, (uint8_t *)&a, 3 * sizeof(uint32_t));
            p->AddConst(a_shares, 1, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 3 * sizeof(uint32_t));
            for (int i = 0; i < 3; i++) {
                view[i]->wireShares.push_back(out_shares[i]);
            }
            //printf("NOT (%d, %d, %d) %d -> (%d, %d, %d) %d\n", a_shares[0], a_shares[1], a_shares[2], (a_shares[0] + a_shares[1] + a_shares[2]) % 2,  out_shares[0], out_shares[1], out_shares[2], (out_shares[0] + out_shares[1] + out_shares[2]) % 2);
            return out;
            //return a;
        }

        uint64_t num_and() override {
            return and_ct;
        }

        block public_label(bool b) override {
            //printf("label\n");
            return makeBlock(0,0);
        }
};

#endif
