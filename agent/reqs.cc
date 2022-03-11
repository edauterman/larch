// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>

#include <iostream>
#include <iomanip>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>

#include "u2f.h"
#include "reqs.h"
#include "asn1.h"
#include "sig_parse.h"
#include "x509.h"
#include "common.h"


#define VENDOR_ID 0x18d1
#define PRODUCT_ID 0x5026

using namespace std;

Params params = Params_new(P256);

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
KeyHandle::KeyHandle(const uint8_t *data)
{
  memcpy(this->data, data, MAX_KH_SIZE);
}

bool KeyHandle::operator<(const KeyHandle &src) const
{
  return memcmp(this->data, src.data, MAX_KH_SIZE) < 0;
}

/* Convert buffers containing x and y coordinates to EC_POINT. */
void bufs_to_pt(const_Params params, const uint8_t *x, const uint8_t *y,
                EC_POINT *pt) {
  uint8_t buf[65];
  buf[0] = 4;
  memcpy(buf + 1, x, 32);
  memcpy(buf + 1 + 32, y, 32);
  EC_POINT_oct2point(Params_group(params), pt, buf, 65, Params_ctx(params));
}

/* Convert EC_POINT to buffers containing x and y coordinates (uncompressed). */
void pt_to_bufs(const_Params params, const EC_POINT *pt, uint8_t *x,
                uint8_t *y) {
  uint8_t buf[65];
  EC_POINT_point2oct(Params_group(params), pt, POINT_CONVERSION_UNCOMPRESSED,
                     buf, 65, Params_ctx(params));
  memcpy(x, buf + 1, 32);
  memcpy(y, buf + 1 + 32, 32);
}

/* Generate key handle using app_id and randomness. */
int
generate_key_handle(const uint8_t *app_id, int app_id_len, uint8_t *key_handle,
                    int key_handle_len)
{
  int rv = ERROR;
  memcpy(key_handle, app_id, app_id_len);
  CHECK_C (RAND_bytes(key_handle + app_id_len, key_handle_len - app_id_len));

cleanup:
  return rv;
}

/* Run registration with origin specified by app_id. Returns sum of lengths of
 * attestation certificate and batch signature. */
int Register(const uint8_t *app_id, const uint8_t *challenge,
             uint8_t *key_handle_out, P256_POINT *pk_out, uint8_t *cert_sig_out) {
  int rv = ERROR;
  EC_POINT *pk;
  string resp_str;
  X509 *cert;
  EC_KEY *anon_key;
  EVP_MD_CTX *evpctx;
  int cert_len = 0;
  int sig_len = 0;
  uint8_t reg_id = U2F_REGISTER_HASH_ID;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  uint8_t signed_data[1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE +
      P256_POINT_SIZE];
  EVP_PKEY *anon_pkey;
  string str;
#ifdef VRF_OPTIMIZED
  cached_vrf *vrf;
#endif
#ifdef HASH2PT_OPTIMIZED
  int num_roots;
#endif

  CHECK_A(pk = Params_point_new(params));
  CHECK_A(cert = X509_new());
  CHECK_A(anon_key = EC_KEY_new());
  CHECK_A(evpctx = EVP_MD_CTX_create());
  CHECK_A(r = BN_new());
  CHECK_A(s = BN_new());
  CHECK_A(anon_pkey = EVP_PKEY_new());

  /* Generate key handle. */
  generate_key_handle(app_id, U2F_APPID_SIZE, key_handle_out, MAX_KH_SIZE);

  /* Output result. */
  // TODO choose keypair
  pk_out->format = UNCOMPRESSED_POINT;

  /* Randomly choose key for attestation. */
  CHECK_C (EC_KEY_set_group(anon_key, Params_group(params)));
  CHECK_C (EC_KEY_generate_key(anon_key));

  /* Generate self-signed cert. */
  cert_len = generate_cert(params, anon_key, cert_sig_out);

  /* Sign hash of U2F_REGISTER_ID, app_id, challenge, kh, and pk with key from
   * self-signed attestation cert. */
  memcpy(signed_data, &reg_id, 1);
  memcpy(signed_data + 1, app_id, U2F_APPID_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE, challenge, U2F_NONCE_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE + U2F_NONCE_SIZE, key_handle_out,
         MAX_KH_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE,
         pk_out, P256_POINT_SIZE);
  CHECK_C(EVP_PKEY_assign_EC_KEY(anon_pkey, anon_key));
  CHECK_C(EVP_SignInit(evpctx, EVP_sha256()));
  CHECK_C(EVP_SignUpdate(evpctx, signed_data, 1 + U2F_APPID_SIZE +
                         U2F_NONCE_SIZE + MAX_KH_SIZE + P256_POINT_SIZE));
  CHECK_C(EVP_SignFinal(evpctx, cert_sig_out + cert_len,
                        (unsigned int *)&sig_len, anon_pkey));

cleanup:
  if (rv == ERROR && pk) EC_POINT_clear_free(pk);
  if (cert) X509_free(cert);
  if (anon_pkey) EVP_PKEY_free(anon_pkey);
  if (evpctx) EVP_MD_CTX_destroy(evpctx);
  return cert_len + sig_len;
}

/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Returns length of signature. */
int Authenticate(const uint8_t *app_id, const uint8_t *challenge,
                 const uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool checkOnly) {
  int rv = ERROR;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  EVP_MD_CTX *mdctx;
  uint8_t message[SHA256_DIGEST_LENGTH];
  ECDSA_SIG *sig = NULL;
  int sig_len = 0;
  uint8_t flags;
  uint8_t ctr[4];

  CHECK_A (r = BN_new());
  CHECK_A (s = BN_new());
  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (sig = ECDSA_SIG_new());

  /* Compute signed message: hash of appId, user presence, counter, and
   * challenge. */
  CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
  CHECK_C (EVP_DigestUpdate(mdctx, app_id, U2F_APPID_SIZE));
  CHECK_C (EVP_DigestUpdate(mdctx, &flags, sizeof(flags)));
  CHECK_C (EVP_DigestUpdate(mdctx, ctr, sizeof(ctr)));
  CHECK_C (EVP_DigestUpdate(mdctx, challenge, U2F_NONCE_SIZE));
  CHECK_C (EVP_DigestFinal_ex(mdctx, message, NULL));

  // TODO: Sign message and produce r,s
  
  /* Output signature. */
  asn1_sigp(sig_out, r, s);

  /* Output message from device. */
  *flags_out = flags;
  memcpy(ctr_out, ctr, sizeof(uint32_t));

cleanup:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  return rv == OKAY ? sig_len : ERROR;
}
