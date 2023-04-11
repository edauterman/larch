#ifndef _SIGS_H_
#define _SIGS_H_

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <vector>

#include "params.h"

void ECDSASign(uint8_t *message_buf, int message_buf_len, const BIGNUM *sk, uint8_t **sig_out, unsigned int *sig_len, Params params);
bool ECDSAVerify(const EC_POINT *pk, BIGNUM *m, BIGNUM *r, BIGNUM *s, Params params);
bool ECDSAVerify(const EC_POINT *pk, uint8_t *message_buf, int message_buf_len, uint8_t *signature, Params params);

#endif
