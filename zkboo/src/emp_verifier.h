#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include "prover.h"
#include "view.h"
#include "verifier.h"
#include "prover_sys.h"

using namespace emp;

static inline void SetWireNum(uint32_t *x, uint32_t wireNum) {
    *x = *x | (wireNum << 1);
}

static inline uint32_t GetWireNum(uint32_t x) {
    return x >> 1;
}

static inline uint32_t GetWireNum(const block &x) {
    uint32_t x32;
    memcpy((uint8_t *)&x32, (uint8_t *)&x, sizeof(uint32_t));
    return GetWireNum(x32);
}

static inline void SetZeroWireNum(uint32_t *x) {
    SetWireNum(x, 1000000000);
}

static inline void SetOneWireNum(uint32_t *x) {
    SetWireNum(x, 2000000000);
}

static inline bool IsZeroWireNum(const block &x) {
    return GetWireNum(x) == 1000000000;
}

static inline bool IsOneWireNum(const block &x) {
    return GetWireNum(x) == 2000000000;
}

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
            //printf("and gate\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
            v->MultShares(a_shares, b_shares, out_shares);
            block out;
            //printf("AND compare %d and %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
/*            if (views[0]->wires[nextWireNum] != out_shares[0]) {
                printf("and gate output failed (%d) -- wanted %d got %d (%d - %d, %d - %d)\n", nextWireNum, views[0]->wires[nextWireNum], out_shares[0], a_shares[0],GetWireNum(a), b_shares[0], GetWireNum(b));
                verified = false;
            }*/
            //out_shares[0] = views[0]->wires[nextWireNum];
            out_shares[1] = in_view->wires[nextWireNum];
            out_view->wires.push_back(out_shares[0]);
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
 
            return out;
            //return a;
        }

        block xor_gate(const block &a, const block &b) override {
            return a ^ b;
            /*//printf("xor gate\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
            v->AddShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            return out;*/
        }

        block not_gate(const block &a) override {
            return a ^ 0xffffffffffffffffffffffff;
            /*uint32_t a_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            v->AddConst(a_shares, 1, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            return out;
            //return a;*/
        }

        uint64_t num_and() override {
            return 0;
        }

        block public_label(bool b) override {
            //printf("label\n");
            if (b == 0) {
                return makeBlock(0,0);
            } else {
                return makeBlock(-1, -1);
            }
        }
};

#endif
