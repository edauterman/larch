#ifndef __SHAMIR_H_INCLUDED__
#define __SHAMIR_H_INCLUDED__

#include <stdint.h>
#include <openssl/bn.h>

#define SHAMIR_MARSHALLED_SIZE 32

typedef struct {
    BIGNUM *x;
    BIGNUM *y;
} ShamirShare;

ShamirShare *ShamirShare_new();
void ShamirShare_free(ShamirShare *share);

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare **shares, BIGNUM **opt_x);
int Shamir_ReconstructShares(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret);
int Shamir_ValidateShares(int t, int n, ShamirShare **shares, BIGNUM *prime);
int Shamir_ReconstructSharesWithValidation(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret);
int Shamir_FindValidShares(int t, int n, ShamirShare **sharesIn, ShamirShare **sharesOut, uint8_t *ordering, BIGNUM *prime, BIGNUM *secret);

void Shamir_MarshalCompressed(uint8_t *buf, ShamirShare *share);
void Shamir_UnmarshalCompressed(uint8_t *buf, uint8_t x, ShamirShare *share);
void Shamir_UnmarshalX(ShamirShare *share, uint8_t x);

int getCoefficients(int t, int n, ShamirShare **shares, const BIGNUM *prime, BIGNUM **cfs, BN_CTX *ctx);
#endif
