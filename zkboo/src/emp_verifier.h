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
        CircuitView *views[2];
        bool verified;
        int gateNum;
        Verifier *v;
        int nextWireNum;

        ZKBooCircExecVerifier(RandomSource *in_rands[], CircuitView *in_views[], int wLen, int idx) {
            for (int i = 0; i < 2; i++) {
                views[i] = in_views[i];
            }
            verified = true;
            gateNum = -1;
            fprintf(stderr, "zkboo: idx = %d\n", idx);
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
            if (views[0]->wires[nextWireNum] != out_shares[0]) {
                printf("and gate output failed (%d) -- wanted %d got %d (%d - %d, %d - %d)\n", nextWireNum, views[0]->wires[nextWireNum], out_shares[0], a_shares[0],GetWireNum(a), b_shares[0], GetWireNum(b));
                verified = false;
            }
            out_shares[0] = views[0]->wires[nextWireNum];
            out_shares[1] = views[1]->wires[nextWireNum];
            //SetWireNum(&out_shares[0], nextWireNum);
            //SetWireNum(&out_shares[1], nextWireNum);
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
 
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
            v->AddShares(a_shares, b_shares, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            return out;
        }

        block not_gate(const block &a) override {
            uint32_t a_shares[2];
            uint32_t out_shares[2];
            memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            v->AddConst(a_shares, 1, out_shares);
            block out;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            return out;
            //return a;
        }

        uint64_t num_and() override {
            return 0;
        }

        block public_label(bool b) override {
            //printf("label\n");
            block out = makeBlock(0,0);
            uint32_t shares[3];
            for (int i = 0; i < 3; i++) {
                shares[i] = b == 0 ? 0 : 0xffffffff; 
                /*if (b == 0) {
                    SetZeroWireNum(&shares[i]);
                } else {
                    SetOneWireNum(&shares[i]);
                }*/
            }
            memcpy((uint8_t *)&out, shares, 3 * sizeof(uint32_t));
            return out;
        }
};

#endif
