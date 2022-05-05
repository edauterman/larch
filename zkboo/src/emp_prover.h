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
    if (val == 0) {
        *x = *x & (val << bit);
    } else {
        *x = *x | (val << bit);
    }
}

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
        CircuitView *verifierViews[2];
        CircuitView *proverViews[3];
        int nextWireNum;
        int id;
        uint32_t idx[32];

        ZKBooCircExecProver(uint8_t seeds[3][32][16], block *w, int wLen, int numRands, uint32_t *idx_in) {
            for (int i = 0; i < 3; i++) {
                proverViews[i] = new CircuitView();
            }
            for (int i = 0; i < 2; i++) {
                verifierViews[i] = new CircuitView();
            }
            p = new Prover(seeds, numRands);
            for (int i = 0; i < wLen; i++) {
                uint32_t shares[3];
                memcpy(shares, (uint8_t *)&w[i], 3 * sizeof(uint32_t));
                uint32_t vals[2];
                for (int j = 0; j < 32; j++) {
                    SetBit(&vals[0], j, GetBit(shares[idx[j]], j));
                    SetBit(&vals[1], j, GetBit(shares[(idx[j] + 1) % 3], j));
                }
                verifierViews[0]->wires.push_back(vals[0]);
                verifierViews[1]->wires.push_back(vals[1]);
                proverViews[0]->wires.push_back(shares[0]);
                proverViews[1]->wires.push_back(shares[1]);
                proverViews[2]->wires.push_back(shares[2]);
            }
            id = rand();
            printf("circexec for id %d\n", id);
            nextWireNum = wLen;
            for (int i = 0; i < 32; i++) {
                idx[i] = idx_in[i];
            }
        }

        ~ZKBooCircExecProver() {
            fprintf(stderr, "****** Num ands: %d -- %d, %d \n", p->numAnds, id, p->id);
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            and_ct++;
            //printf("and gate, %d\n", nextWireNum);
            uint32_t a_shares[3];
            uint32_t b_shares[3];
            uint32_t out_shares[3];
            memcpy(a_shares, (uint8_t *)&a, 3 * sizeof(uint32_t));
            memcpy(b_shares, (uint8_t *)&b, 3 * sizeof(uint32_t));
            p->MultShares(a_shares, b_shares, out_shares);
            block out;
            uint32_t vals[2];
            for (int j = 0; j < 32; j++) {
                SetBit(&vals[0], j, GetBit(out_shares[idx[j]], j));
                SetBit(&vals[1], j, GetBit(out_shares[(idx[j] + 1) % 3], j));
            }
            verifierViews[0]->wires.push_back(vals[0]);
            verifierViews[1]->wires.push_back(vals[1]);
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
            printf("id = %d\n", p->id);
            return p->numAnds;
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
