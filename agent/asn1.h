// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef __CROS_EC_INCLUDE_ASN1_H
#define __CROS_EC_INCLUDE_ASN1_H

#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "params.h"

// Tags we care about
enum {
  t_NULL = 0x00,
  t_INT = 0x02,
  t_BITS = 0x03,
  t_BYTES = 0x04,
  t_OBJ = 0x06,
  t_UTF8 = 0x0c,
  t_ASCII = 0x13,
  t_TIME = 0x18,
  t_SEQ = 0x30,
  t_SET = 0x31,
};

typedef struct {
  uint8_t* p;
  size_t n;
} ASN1;

// Write a tag and return write ptr
uint8_t* asn1_tag(ASN1* ctx, uint8_t tag);

// DER encode length and return encoded size thereof
int asn1_len(uint8_t* p, size_t size);

// Reserve space for seq tlv encoding
#define SEQ_SMALL 2   // < 128 bytes
#define SEQ_MEDIUM 3  // < 256 bytes
#define SEQ_LARGE 4   // < 65536 bytes

#define SEQ_START(X, T, L) \
  do {                     \
    int __old = (X).n;     \
    uint8_t __t = (T);     \
    int __l = (L);         \
    (X).n += __l;
#define SEQ_END(X)                                                        \
  (X).n = asn1_seq((X).p + __old, __t, __l, (X).n - __old - __l) + __old; \
  }                                                                       \
  while (0)

// Close sequence and move encapsulated data if needed
// Return total length
size_t asn1_seq(uint8_t* p, uint8_t tag, size_t l, size_t size);

// DER encode (small positive) integer
void asn1_int(ASN1* ctx, uint32_t val);

// DER encode bignum
void asn1_bignum(ASN1* ctx, const BIGNUM* n);

// DER encode signature sequence (no OID).
void asn1_sig(ASN1* ctx, const BIGNUM* r, const BIGNUM* s);

// DER encode public key.
void asn1_pub(ASN1* ctx, const_Params params, const EC_POINT *pk);

// DER encode printable string
void asn1_string(ASN1* ctx, uint8_t tag, const char* s);

// DER encode bytes
void asn1_object(ASN1* ctx, size_t n, const uint8_t* b);

size_t asn1_sigp(uint8_t* buf, const BIGNUM* r, const BIGNUM* s);

extern const uint8_t OID_commonName[3];
extern const uint8_t OID_organizationName[3];
extern const uint8_t OID_ecdsa_with_SHA256[8];
extern const uint8_t OID_id_ecPublicKey[7];
extern const uint8_t OID_prime256v1[8];
extern const uint8_t OID_fido_u2f[11];

#define OID(X) sizeof(OID_##X), OID_##X

#endif
