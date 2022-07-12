// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdio.h>
#include <string.h>
#include "asn1.h"
#include "u2f.h"

// start a tag and return write ptr
uint8_t* asn1_tag(ASN1* ctx, uint8_t tag) {
  ctx->p[(ctx->n)++] = tag;
  return ctx->p + ctx->n;
}

// DER encode length and return encoded size thereof
int asn1_len(uint8_t* p, size_t size) {
  if (size < 128) {
    p[0] = size;
    return 1;
  } else if (size < 256) {
    p[0] = 0x81;
    p[1] = size;
    return 2;
  } else {
    p[0] = 0x82;
    p[1] = size >> 8;
    p[2] = size;
    return 3;
  }
}

// close sequence and move encapsulated data if needed
// return total length
size_t asn1_seq(uint8_t* p, uint8_t tag, size_t l, size_t size) {
  size_t tl;

  p[0] = tag;
  tl = asn1_len(p + 1, size) + 1;
  // TODO: tl > l fail
  if (tl < l) {
    memmove(p + tl, p + l, size);
  }
  return tl + size;
}

// DER encode (small positive) integer
void asn1_int(ASN1* ctx, uint32_t val) {
  uint8_t* p = asn1_tag(ctx, t_INT);

  if (!val) {
    *p++ = 1;
    *p++ = 0;
  } else {
    int nbits = 32 - __builtin_clz(val);
    int nbytes = (nbits + 7) / 8;
    if ((nbits & 7) == 0) {
      *p++ = nbytes + 1;
      *p++ = 0;
    } else {
      *p++ = nbytes;
    }
    while (nbytes--) {
      *p++ = val >> (nbytes * 8);
    }
  }

  ctx->n = p - ctx->p;
}

// DER encode bignum
void asn1_bignum(ASN1* ctx, const BIGNUM* n) {
  uint8_t* p = asn1_tag(ctx, t_INT);
  uint8_t bn[P256_SCALAR_SIZE];
  int i;

  BN_bn2bin(n, bn);
  for (i = 0; i < P256_SCALAR_SIZE; ++i) {
    if (bn[i] != 0) break;
  }
  if (bn[i] & 0x80) {
    *p++ = P256_SCALAR_SIZE - i + 1;
    *p++ = 0;
  } else {
    *p++ = P256_SCALAR_SIZE - i;
  }
  for (; i < P256_SCALAR_SIZE; ++i) {
    *p++ = bn[i];
  }

  ctx->n = p - ctx->p;
}

// DER encode p256 signature
void asn1_sig(ASN1* ctx, const BIGNUM* r, const BIGNUM* s) {
  SEQ_START(*ctx, t_SEQ, SEQ_SMALL) {
    asn1_bignum(ctx, r);
    asn1_bignum(ctx, s);
  }
  SEQ_END(*ctx);
}

// DER encode printable string
void asn1_string(ASN1* ctx, uint8_t tag, const char* s) {
  uint8_t* p = asn1_tag(ctx, tag);
  size_t n = strlen(s);

  p += asn1_len(p, n);
  while (n--) {
    *p++ = *s++;
  }

  ctx->n = p - ctx->p;
}

// DER encode bytes
void asn1_object(ASN1* ctx, size_t n, const uint8_t* b) {
  uint8_t* p = asn1_tag(ctx, t_OBJ);

  p += asn1_len(p, n);
  while (n--) {
    *p++ = *b++;
  }

  ctx->n = p - ctx->p;
}

// DER encode pk
void asn1_pub(ASN1* ctx, const_Params params, const EC_POINT *pk) {
  uint8_t buf[65];
  EC_POINT_point2oct(Params_group(params), pk, POINT_CONVERSION_UNCOMPRESSED, buf, 65, Params_ctx(params));
  uint8_t* p = asn1_tag(ctx, 4);  // uncompressed format

  memcpy(p, buf + 1, P256_SCALAR_SIZE);
  p += P256_SCALAR_SIZE;
  memcpy(p, buf + 1 + P256_SCALAR_SIZE, P256_SCALAR_SIZE);
  p += P256_SCALAR_SIZE;

  ctx->n = p - ctx->p;
}

size_t asn1_sigp(uint8_t* buf, const BIGNUM* r, const BIGNUM* s) {
  ASN1 asn1 = {buf, 0};

  asn1_sig(&asn1, r, s);
  return asn1.n;
}

const uint8_t OID_commonName[3] = {0x55, 0x04, 0x03};
const uint8_t OID_organizationName[3] = {0x55, 0x04, 0x0a};
const uint8_t OID_ecdsa_with_SHA256[8] = {0x2A, 0x86, 0x48, 0xCE,
                                          0x3D, 0x04, 0x03, 0x02};
const uint8_t OID_id_ecPublicKey[7] = {0x2A, 0x86, 0x48, 0xCE,
                                       0x3D, 0x02, 0x01};
const uint8_t OID_prime256v1[8] = {0x2A, 0x86, 0x48, 0xCE,
                                   0x3D, 0x03, 0x01, 0x07};
const uint8_t OID_fido_u2f[11] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
                                  0xE5, 0x1C, 0x02, 0x01, 0x01};
