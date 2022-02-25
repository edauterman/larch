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
        CircuitView *views[2];
        bool verified;
        int gateNum;
        Verifier *v;

        ZKBooCircExecVerifier(RandomSource in_rands[], CircuitView *in_views[]) {
            for (int i = 0; i < 2; i++) {
                views[i] = in_views[i];
            }
            verified = true;
            gateNum = 0;
            v = new Verifier(in_rands);
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            //printf("and gate\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                //printf("and gate input (v0) failed\n");
                verified = false;
            }
            if (views[1]->wireShares[gateNum] != b_shares[0]) {
                //printf("and gate input (v1) failed\n");
                verified = false;
            }
            v->MultShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            if (views[0]->wireShares[gateNum] != out_shares[0]) {
                //printf("and gate output failed\n");
                verified = false;
            } 
            return out;
            //return a;
        }

        block xor_gate(const block &a, const block &b) override {
            //printf("xor gate\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                //printf("xor gate input (v0) failed\n");
                verified = false;
            }
            if (views[1]->wireShares[gateNum] != b_shares[0]) {
                //printf("xor gate input (v1) failed\n");
                verified = false;
            }
            v->AddShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            if (views[0]->wireShares[gateNum] != out_shares[0]) {
                //printf("xor gate output failed\n");
                verified = false;
            } 
            return out;
        }

        block not_gate(const block &a) override {
            //printf("not\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                //printf("not gate input failed\n");
                verified = false;
            } 
            v->AddConst(a_shares, 1, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            if (views[0]->wireShares[gateNum] != out_shares[0]) {
                //printf("not gate output failed\n");
                verified = false;
            } 
            return out;
            //return a;
        }

        uint64_t num_and() override {
            return 0;
        }

        block public_label(bool b) override {
            //printf("label\n");
            return makeBlock(0,0);
        }
};

#endif
