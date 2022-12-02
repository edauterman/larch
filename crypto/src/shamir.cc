#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <string>
#include <algorithm>

#include "common.h"
#include "shamir.h"

/* Shamir secret sharing. */

using namespace std;

ShamirShare *ShamirShare_new() {
    int rv;
    ShamirShare *share = NULL;

    CHECK_A (share = (ShamirShare *)malloc(sizeof(ShamirShare)));
    CHECK_A (share->x = BN_new());
    CHECK_A (share->y = BN_new());
cleanup:
    if (rv == OKAY) return share;
    ShamirShare_free(share);
    return NULL;
}

void ShamirShare_free(ShamirShare *share) {
    if (share->x) BN_free(share->x);
    if (share->y) BN_free(share->y);
    if (share) free(share);
}

/* Given polynomial defined by t a's, evaluate at x and place result in y. */
int evalPolynomial(BIGNUM **a, int t, BIGNUM *x, BIGNUM *y, BIGNUM *prime, BN_CTX *ctx) {
    int rv;
    BIGNUM *currX = NULL;
    BIGNUM *currTerm = NULL;

    CHECK_A (currX = BN_new());
    CHECK_A (currTerm = BN_new());
    BN_one(currX);
    BN_zero(y);

    for (int i = 0; i < t; i++) {
        CHECK_C (BN_mod_mul(currTerm, a[i], currX, prime, ctx));
        CHECK_C (BN_mod_add(y, y, currTerm, prime, ctx));
        CHECK_C (BN_mod_mul(currX, currX, x, prime, ctx));
    }
cleanup:
    if (currX) BN_free(currX);
    if (currTerm) BN_free(currTerm);
    return rv;
}

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare **shares, BIGNUM **opt_x) {
    int rv;
    BIGNUM *a[t];
    BN_CTX *ctx = NULL;

    CHECK_A (ctx = BN_CTX_new());

    /* Set a_0 = secret. */
    CHECK_A (a[0] = BN_dup(secret));
    /* Generate t-1 random a's to define polynomial. */
    for (int i = 1; i < t; i++) {
        CHECK_A (a[i] = BN_new());
        CHECK_C (BN_rand_range(a[i], prime));
    }

    /* Generate s random x's to evaluate polynomial at. */
    for (int i = 0; i < n; i++) {
        if (opt_x == NULL) {
            CHECK_C (BN_rand_range(shares[i]->x, prime));
        } else {
            BN_copy(shares[i]->x, opt_x[i]);
        }
        CHECK_C (evalPolynomial(a, t, shares[i]->x, shares[i]->y, prime, ctx));
    }

cleanup:
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int getCoefficients(int t, int n, ShamirShare **shares, const BIGNUM *prime, BIGNUM **cfs, BN_CTX *ctx) {
    int rv;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;

    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());

    for (int i = 0; i < t; i++) {
        BN_one(cfs[i]);
        for (int j = 0; j < t; j++) {
            if (i == j) continue;
            /* lambda = \prod_{j=1, j!=i}^t 1 / (x_i - x_j) */
            CHECK_C (BN_mod_sub(denominator, shares[i]->x, shares[j]->x, prime, ctx));
            BN_mod_inverse(denominatorInverse, denominator, prime, ctx);
            CHECK_C (BN_mod_mul(cfs[i], cfs[i], denominatorInverse, prime, ctx));
        }
        CHECK_C (BN_mod_mul(cfs[i], cfs[i], shares[i]->y, prime, ctx));
    }

cleanup:
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    return rv;
}

int evalWithCoefficients(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM **cfs, BIGNUM *x, BIGNUM *result, BN_CTX *ctx) {
    int rv;
    BIGNUM *prod = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *tmpInv = NULL;
    BIGNUM *curr = NULL;

    CHECK_A (prod = BN_new());
    CHECK_A (tmp = BN_new());
    CHECK_A (tmpInv = BN_new());
    CHECK_A (curr = BN_new());
    BN_one(prod);
    BN_zero(result);

    /* \prod_{j=1}^t (x - x_j) */
    for (int i = 0; i < t; i++) {
        CHECK_C (BN_mod_sub(tmp, x, shares[i]->x, prime, ctx));
        CHECK_C (BN_mod_mul(prod, prod, tmp, prime, ctx));
    }

    for (int i = 0; i < t; i++) {
        /* Divide out (x - x_i) */
        CHECK_C (BN_mod_sub(tmp, x, shares[i]->x, prime, ctx));
        BN_mod_inverse(tmpInv, tmp, prime, ctx);
        CHECK_C (BN_mod_mul(curr, prod, tmpInv, prime, ctx));
        /* Multiply by coefficient and add */
        CHECK_C (BN_mod_mul(curr, curr, cfs[i], prime, ctx));
        CHECK_C (BN_mod_add(result, result, curr, prime, ctx));
    }

cleanup:
    if (prod) BN_free(prod);
    if (tmp) BN_free(tmp);
    if (tmpInv) BN_free(tmpInv);
    if (curr) BN_free(curr);
    return rv;
}

int Shamir_ReconstructShares(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret) {
    int rv;
    BIGNUM *cfs[t];
    BIGNUM *zero;
    BN_CTX *ctx;

    for (int i = 0; i < t; i++) {
        CHECK_A (cfs[i] = BN_new());
    }
    CHECK_A (zero = BN_new());
    CHECK_A (ctx = BN_CTX_new());
    BN_zero(zero);

    CHECK_C (getCoefficients(t, n, shares, prime, cfs, ctx));
    CHECK_C (evalWithCoefficients(t, n, shares, prime, cfs, zero, secret, ctx));

cleanup:
    if (zero) BN_free(zero);
    if (ctx) BN_CTX_free(ctx);
    for (int i = 0; i < t; i++) {
        if (cfs[i]) BN_free(cfs[i]);
    }
    return rv;
}

/*  validShareIndexes of length t, if NULL don't fill in */
int Shamir_ValidateShares(int t, int n, ShamirShare **shares, BIGNUM *prime) {
    int rv;
    BIGNUM *cfs[t];
    BIGNUM *y;
    BN_CTX *ctx;
    int ctr = 0;

    for (int i = 0; i < t; i++) {
        CHECK_A (cfs[i] = BN_new());
    }
    CHECK_A (y = BN_new());
    CHECK_A (ctx = BN_CTX_new());

    CHECK_C (getCoefficients(t, n, shares, prime, cfs, ctx));
    for (int i = t; i < n; i++) {
        CHECK_C (evalWithCoefficients(t, n, shares, prime, cfs, shares[i]->x, y, ctx));
        if (BN_cmp(y, shares[i]->y) == 0) {
            ctr++;
        }
    }
    return ctr >= t ? OKAY : ERROR; 

cleanup:
    if (y) BN_free(y);
    if (ctx) BN_CTX_free(ctx);
    for (int i = 0; i < t; i++) {
        if (cfs[i]) BN_free(cfs[i]);
    }
    return rv;
}

int Shamir_ReconstructSharesWithValidation(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret) {
    int rv; 
    ShamirShare **currShares = NULL;
    string bitmask(t, 1); 
    bitmask.resize(n, 0); 

    CHECK_A (currShares = (ShamirShare **)malloc(n * sizeof(ShamirShare *)));

    do {
        int j = 0;
        for (int i = 0; i < n; i++) {
            if (bitmask[i]) {
                currShares[j] = shares[i];
                j++;
            }   
        }   
        for (int i = 0; i < n; i++) {
            if (!bitmask[i]) {
                currShares[j] =  shares[i];
                j++;
            }   
        }   
        if (Shamir_ValidateShares(t, n, currShares, prime) == OKAY) {
            CHECK_C (Shamir_ReconstructShares(t, n, currShares, prime, secret));
            goto cleanup;
        }   
    } while (prev_permutation(bitmask.begin(), bitmask.end()));
    printf("No valid reconstruction");
    rv = ERROR;

cleanup:
    if (currShares) free(currShares);
    return rv; 
}

/* sharesIn of length n, sharesOut of length 2t, ordering is combination of indexes
 * of sharesIn that are in sharesOut (ordering is 1-indexed). */
int Shamir_FindValidShares(int t, int n, ShamirShare **sharesIn, ShamirShare **sharesOut, uint8_t *ordering, BIGNUM *prime, BIGNUM *secret) {
    int rv; 
    string bitmask(2 * t, 1); 
    bitmask.resize(n, 0); 

    do {
        int j = 0;
        for (int i = 0; i < n; i++) {
            if (bitmask[i]) {
                sharesOut[j] = sharesIn[i];
                ordering[j] = i + 1;
                j++;
            }   
        }   
        if (Shamir_ValidateShares(t, 2 * t, sharesOut, prime) == OKAY) {
            CHECK_C (Shamir_ReconstructShares(t, 2 * t, sharesOut, prime, secret));
            printf("Found reconstruction\n");
            goto cleanup;
        }   
    } while (prev_permutation(bitmask.begin(), bitmask.end()));
    printf("No valid reconstruction\n");
    rv = ERROR;

cleanup:
    return rv; 
}

void Shamir_MarshalCompressed(uint8_t *buf, ShamirShare *share) {
    memset(buf, 0, 32);
    BN_bn2bin(share->y, buf + 32 - BN_num_bytes(share->y));
}

void Shamir_UnmarshalCompressed(uint8_t *buf, uint8_t x, ShamirShare *share) {
    BN_bin2bn(&x, 1, share->x);
    BN_bin2bn(buf, 32, share->y);
}

void Shamir_UnmarshalX(ShamirShare *share, uint8_t x) {
    BN_bin2bn(&x, 1, share->x);
}
