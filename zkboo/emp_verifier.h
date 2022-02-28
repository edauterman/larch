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
            v = new Verifier(in_rands, idx);
            nextWireNum = wLen;
        }


        // each block is a share of 3 wire values

        block and_gate(const block &a, const block &b) override {
            //printf("and gate\n");
            uint32_t a_shares[2];
            uint32_t b_shares[2];
            uint32_t out_shares[2];
            for (int i = 0; i < 2; i++) {
                a_shares[i] = views[i]->wireMap[GetWireNum(a)];
                b_shares[i] = views[i]->wireMap[GetWireNum(b)];
            }
            //memcpy(a_shares, (uint8_t *)&a, 2 * sizeof(uint32_t));
            //memcpy(b_shares, (uint8_t *)&b, 2 * sizeof(uint32_t));
/*            if (gateNum != -1) {
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                if (verified) printf("and gate input (v0) failed\n");
                verified = false;
            }
            if (views[1]->wireShares[gateNum] != b_shares[0]) {
                if (verified) printf("and gate input (v1) failed\n");
                verified = false;
            }
            }*/
            v->MultShares(a_shares, b_shares, out_shares);
            block out;
            //printf("AND compare %d and %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
            if (views[0]->wireMap[nextWireNum] != out_shares[0]) {
                printf("and gate output failed %d %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
                verified = false;
            }
            SetWireNum(&out_shares[0], nextWireNum);
            SetWireNum(&out_shares[1], nextWireNum);
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
            for (int i = 0; i < 2; i++) {
                a_shares[i] = views[i]->wireMap[GetWireNum(a)];
                b_shares[i] = views[i]->wireMap[GetWireNum(b)];
            }
 
/*            if (gateNum != -1) {
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                if (verified) printf("xor gate input (v0) failed %d %d\n", views[0]->wireShares[gateNum], a_shares[0]);
                verified = false;
            }
            if (views[1]->wireShares[gateNum] != b_shares[0]) {
                if (verified) printf("xor gate input (v1) failed %d %d\n", views[1]->wireShares[gateNum], b_shares[0]);
                verified = false;
            }
            }*/
            v->AddShares(a_shares, b_shares, out_shares);
            block out;
            //printf("XOR compare %d and %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
            if (views[0]->wireMap[nextWireNum] != out_shares[0]) {
                printf("xor gate output failed %d %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
                verified = false;
            }
            SetWireNum(&out_shares[0], nextWireNum);
            SetWireNum(&out_shares[1], nextWireNum);
            nextWireNum++;
            memcpy((uint8_t *)&out, out_shares, 2 * sizeof(uint32_t));
            gateNum++;
            return out;
        }

        block not_gate(const block &a) override {
            //printf("not\n");
            uint32_t a_shares[2];
            uint32_t out_shares[2];
            for (int i = 0; i < 2; i++) {
                a_shares[i] = views[i]->wireMap[GetWireNum(a)];
            }
/*            if (gateNum != -1) {
            if (views[0]->wireShares[gateNum] != a_shares[0]) {
                if (verified) printf("not gate input failed\n");
                verified = false;
            } 
            }*/
            v->AddConst(a_shares, 1, out_shares);
            block out;
            //printf("NOT compare %d and %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
           if (views[0]->wireMap[nextWireNum] != out_shares[0]) {
                printf("not gate output failed %d %d\n", views[0]->wireMap[nextWireNum], out_shares[0]);
                verified = false;
            }
            SetWireNum(&out_shares[0], nextWireNum);
            SetWireNum(&out_shares[1], nextWireNum);
            nextWireNum++;
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
            return makeBlock(0,0);
        }
};

#endif
