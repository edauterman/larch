#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#include "verifier.h"
#include "prover.h"
#include "proof.h"
#include "view.h"
#include "circuit.h"
#include "emp_verifier.h"
#include "../../crypto/params.h"

using namespace std;
using namespace emp;


static inline bool GetBit(uint32_t x, int bit) {
    return (bool)((x & (1 << bit)) >> bit);
}

static inline void SetBit(uint32_t *x, int bit, bool val) {
    *x = *x | (val << bit);
}

Verifier::Verifier(RandomSource *in_rands[], uint32_t *in_idx) {
    rands[0] = in_rands[0];
    rands[1] = in_rands[1];
    currGate = 0;
    for (int i = 0; i < 32; i++) {
        idx[i] = in_idx[i];
    }
    numAnds = 0;
    for (int i = 0; i < 2; i++) {
        one_mask[i] = 0;
        for (int j = 0; j < 32; j++) {
            if (((idx[j] + 1) % 3) == 0) {
                SetBit(&one_mask[i], j, 1);
            }
        }
    }
}

inline void Verifier::AddConst(uint32_t a[], uint8_t alpha, uint32_t out[]) {
    currGate++;
    for (int i = 0; i < 2; i++) {
        out[i] = 0xffffffff ^ a[i];
    }
}

inline void Verifier::AddShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    for (int i = 0; i < 2; i++) {
        out[i] = a[i] ^ b[i];
    }
}

inline void Verifier::MultShares(uint32_t a[], uint32_t b[], uint32_t out[]) {
    currGate++;
    uint32_t masks[2];
    for (int i = 0; i < 2; i++) {
        masks[i] = 0; 
        for (int j = 0; j < 32; j++) {
            masks[i] = masks[i] | (GetBit(rands[i]->randomness[j][numAnds/8], numAnds%8) << j);
        }
    }
    out[0] = ((a[0] & b[0]) ^ (a[1] & b[0]) ^ (a[0] & b[1])
            ^ masks[0] ^ masks[1]);
    numAnds++;
}

void AssembleShares(uint32_t *in0, uint32_t *in1, uint32_t *in2, uint8_t *out, int num_blocks) {
    bool *bs = new bool[num_blocks];
    for (int i = 0; i < num_blocks; i++) {
        bs[i] = in0[i] ^ in1[i] ^ in2[i];
    }
    from_bool(bs, out, num_blocks);
}

bool VerifyCtCircuit(Proof *proof, __m128i iv, int m_len, int in_len, uint8_t * hashOutRaw, uint8_t *keyCommRaw, uint8_t *ctRaw, bool *ret) {
    for (int i = 0; i < 32; i++) {
        CircuitComm c;
        proof->view->Commit(c, i, proof->openings[1][i]);
        if (memcmp(c.digest, proof->comms[(proof->idx[i] + 1) % 3][i].digest, SHA256_DIGEST_LENGTH) != 0) {
            fprintf(stderr, "zkboo: commit for c1 (input) failed\n");
            *ret = false;
            return false;
        }
    }

    RandomOracle oracle;
    for (int i = 0; i < 32; i++) {
        uint8_t idx_check = oracle.GetRand(proof->comms[0][i], proof->comms[1][i], proof->comms[2][i]);
        if (proof->idx[i] != idx_check) {
            fprintf(stderr, "zkboo: idx = %d, should equal %d\n", idx_check, proof->idx[i]);
            *ret = false;
            return false;
        }
    }

    block *m = new block[m_len];
    block *hashOut = new block[256];
    block *ct = new block[m_len];
    block *key = new block[128];
    block *keyR = new block[128];
    block *keyComm = new block[256];
    block *hashIn = new block[in_len];
    block *out = new block[1];

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&m[i], (uint8_t *)&proof->w[0][i], sizeof(uint32_t));
        memcpy((uint8_t *)&m[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i], sizeof(uint32_t));
    }

    for (int i = 0; i < 256; i++) {
        memcpy((uint8_t *)&hashOut[i], (uint8_t *)&proof->w[0][i + m_len], sizeof(uint32_t));
        memcpy((uint8_t *)&hashOut[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len], sizeof(uint32_t));
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 32; k++) {
                if (GetBit(proof->w[j][i+m_len], k) != GetBit(proof->pubInShares[(j + proof->idx[k]) % 3][i], k)) {
                    fprintf(stderr, "zkboo: public input shares don't match (hashOut) i=%d j=%d k=%d -- %d %d\n", i, j, k, proof->w[j][i + m_len], proof->pubInShares[(j+proof->idx[k])%3][i]);
                    *ret = false;
                    return false;
                }
            }
        }
    }

    for (int i = 0; i < m_len; i++) {
        memcpy((uint8_t *)&ct[i], (uint8_t *)&proof->w[0][i + m_len + 256], sizeof(uint32_t));
        memcpy((uint8_t *)&ct[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len + 256], sizeof(uint32_t));
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 32; k++) {
                if (GetBit(proof->w[j][i+m_len+256], k) != GetBit(proof->pubInShares[(j + proof->idx[k]) % 3][i + 256 + 256], k)) {
                    fprintf(stderr, "zkboo: public input shares don't match (ct)\n");
                    *ret = false;
                    return false;
                }
            }
 
        }
    }

    for (int i = 0; i < 128; i++) {
        memcpy((uint8_t *)&key[i], (uint8_t *)&proof->w[0][i + m_len + 256 + m_len], sizeof(uint32_t));
        memcpy((uint8_t *)&key[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len + 256 + m_len], sizeof(uint32_t));
    }

    for (int i = 0; i < 128; i++) {
        memcpy((uint8_t *)&keyR[i], (uint8_t *)&proof->w[0][i + m_len + 256 + m_len + 128], sizeof(uint32_t));
        memcpy((uint8_t *)&keyR[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len + 256 + m_len + 128], sizeof(uint32_t));
    }

    for (int i = 0; i < 256; i++) {
        memcpy((uint8_t *)&keyComm[i], (uint8_t *)&proof->w[0][i + m_len + 256 + m_len + 128 + 128], sizeof(uint32_t));
        memcpy((uint8_t *)&keyComm[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len + 256 + m_len + 128 + 128], sizeof(uint32_t));
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 32; k++) {
                if (GetBit(proof->w[j][i+m_len+256+m_len+128+128], k) != GetBit(proof->pubInShares[(j + proof->idx[k]) % 3][i + 256], k)) {
                    fprintf(stderr, "zkboo: public input shares don't match (keyComm)\n");
                    *ret = false;
                    return false;
                }
            }
        }
    }

    for (int i = 0; i < in_len; i++) {
        memcpy((uint8_t *)&hashIn[i], (uint8_t *)&proof->w[0][i + m_len + 256 + m_len + 128 + 128 + 256], sizeof(uint32_t));
        memcpy((uint8_t *)&hashIn[i] + sizeof(uint32_t), (uint8_t *)&proof->w[1][i + m_len + 256 + m_len + 128 + 128 + 256], sizeof(uint32_t));
    }
    
    uint8_t *hashOutTest = (uint8_t *)malloc(256 / 8);
    uint8_t *keyCommTest = (uint8_t *)malloc(256 / 8);
    uint8_t *ctTest = (uint8_t *)malloc(m_len / 8);
    AssembleShares(proof->pubInShares[0], proof->pubInShares[1], proof->pubInShares[2], hashOutTest, 256);
    AssembleShares(proof->pubInShares[0] + 256, proof->pubInShares[1] + 256, proof->pubInShares[2] + 256, keyCommTest, 256);
    AssembleShares(proof->pubInShares[0] + 512, proof->pubInShares[1] + 512, proof->pubInShares[2] + 512, ctTest, m_len);
    if (memcmp(hashOutTest, hashOutRaw, 256 / 8) != 0) {
        *ret = false;
        return false;
    }
    if (memcmp(keyCommTest, keyCommRaw, 256 / 8) != 0) {
        *ret = false;
        return false;
    }
    if (memcmp(ctTest, ctRaw, m_len / 8) != 0) {
        *ret = false;
        return false;
    }
    uint32_t outTest = (proof->outShares[0][0] + proof->outShares[1][0] + proof->outShares[2][0]) % 2;
    for (int i = 0; i < 32; i++) {
        uint32_t res = ((GetBit(proof->outShares[0][0], i) + GetBit(proof->outShares[1][0], i) + GetBit(proof->outShares[2][0], i)) % 2);
        if (((GetBit(proof->outShares[0][0], i) + GetBit(proof->outShares[1][0], i) + GetBit(proof->outShares[2][0], i)) % 2) != 1) {
            printf("for %d -> %d, %d, %d -> %d\n", i, proof->outShares[0][0], proof->outShares[1][0], proof->outShares[2][0], res);
            *ret = false;
            return false; 
        }
    }

    ZKBooCircExecVerifier<AbandonIO> *ex = new ZKBooCircExecVerifier<AbandonIO>(proof->rands, proof->view, proof->w[0], proof->wLen, proof->idx);
    CircuitExecution::circ_exec = ex;
    check_ciphertext_circuit(ex, hashOut, m, m_len, hashIn, in_len, ct, iv, key, keyComm, keyR, out);
    
    for (int i = 0; i < 32; i++) {
        CircuitComm c;
        ex->out_view->Commit(c, i, proof->openings[0][i]);

        if (memcmp(c.digest, proof->comms[proof->idx[i]][i].digest, SHA256_DIGEST_LENGTH) != 0) {
            fprintf(stderr, "zkboo: commit for c0 (output) failed\n");
            *ret = false;
            return false;
        }
    }
    
    if (ex->verified) {
        *ret = true;
        return true;
    } else {
        *ret = true;
        return false;
    }

    *ret = true; 
    return true;
    
}

