#ifndef _EMP_PROVER_H_
#define _EMP_PROVER_H_

#include <emp-tool/emp-tool.h>
#include "emp-tool/execution/circuit_execution.h"
#include "prover.h"
#include "view.h"

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
class ZKBooCircExecProver : public CircuitExecution {
    public:
        uint64_t and_ct = 0;
        //int wireIdx;
        Prover *p;
        CircuitView *view[3];
        int nextWireNum;

        ZKBooCircExecProver(uint8_t *seeds[], block *w, int wLen, int numRands) {
            for (int i = 0; i < 3; i++) {
                view[i] = new CircuitView();
            }
            p = new Prover(seeds, numRands);
            for (int i = 0; i < wLen; i++) {
                uint32_t shares[3];
                memcpy(shares, (uint8_t *)&w[i], 3 * sizeof(uint32_t));
                for (int j = 0; j < 3; j++) {
                    view[j]->wires.push_back(shares[j] & 1);
                }
            }
            nextWireNum = wLen;
        }

        ~ZKBooCircExecProver() {
            fprintf(stderr, "****** Num ands: %d\n", p->numAnds);
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
            for (int i = 0; i < 3; i++) {
                view[i]->wires.push_back(out_shares[i]);
                //SetWireNum(&out_shares[i], nextWireNum);
            }
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 3 * sizeof(uint32_t));
            //printf("AND (%d %d %d) %d %d -> (%d %d %d) %d\n", a_shares[0], a_shares[1], a_shares[2], a_shares[0] ^ a_shares[1] ^ a_shares[2], b_shares[0] ^ b_shares[1] ^ b_shares[2], out_shares[0], out_shares[1], out_shares[2], out_shares[0] ^ out_shares[1] ^ out_shares[2]);
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
            //printf("XOR (%d %d %d) %d %d -> (%d %d %d) %d\n", a_shares[0], a_shares[1], a_shares[2], a_shares[0] ^ a_shares[1] ^ a_shares[2], b_shares[0] ^ b_shares[1] ^ b_shares[2], out_shares[0], out_shares[1], out_shares[2], out_shares[0] ^ out_shares[1] ^ out_shares[2]);
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
            //printf("NOT (%d, %d, %d) %d -> (%d, %d, %d) %d\n", a_shares[0], a_shares[1], a_shares[2], (a_shares[0] ^ a_shares[1] ^ a_shares[2]),  out_shares[0], out_shares[1], out_shares[2], (out_shares[0] ^ out_shares[1] ^ out_shares[2]));
            return out;
        }

        uint64_t num_and() override {
            return and_ct;
        }

        block public_label(bool b) override {
            //printf("label\n");
            block out = makeBlock(0,0);
            uint32_t shares[3];
            for (int i = 0; i < 3; i++) {
                shares[i] = b == 0 ? 0 : 0xffffffff;
            }
            memcpy((uint8_t *)&out, shares, 3 * sizeof(uint32_t));
            return out;
        }
};

#endif
