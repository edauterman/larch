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
#include <json.hpp>
#include <string>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

//#include "agent.h"
#include "common.h"
#include "base64.h"
#include "u2f.h"
#include "client.h"
#include "x509.h"
#include "asn1.h"

// Used to define JSON messages.
#define ID "agent-det2f"
#define AUTH_REQ "sign_helper_request"
#define AUTH_RESP "sign_helper_reply"
#define REG_REQ "enroll_helper_request"
#define REG_RESP "enroll_helper_reply"
#define TYPE "type"
#define CODE "code"
#define VERSION "version"
#define ENROLL_CHALLENGES "enrollChallenges"
#define APP_ID "app_id"
#define CHALLENGE "challenge"
#define KEY_HANDLE "key_handle"
#define PUB_KEY "public_key"
#define ENROLL_DATA "enrollData"
#define SIGN_DATA "signData"
#define RESPONSE_DATA "responseData"
#define SIGNATURE "signature"
#define COUNTER "counter"
#define DEVICE_OK 0
#define DEVICE_ERR 0x6984
#define U2F_V2 "U2F_V2"
#define KH_FILE "~/kh_file.txt"

using namespace std;
using namespace nlohmann;

struct message_t {
  string content;
  uint32_t length;
};

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

Client::Client() {
    params = Params_new(P256);
}

/* Write agent state to file, including root public keys and map of key handles
 * to public keys. Should be called when creating a new agent. */
// TODO: error checking
void Client::WriteToStorage() {
  /* Write mpk and pk_vrf. */
/*  uint8_t mpk_buf[33];
  uint8_t pk_vrf_buf[33];
  FILE *pk_file = fopen(PK_FILE, "w");
  EC_POINT_point2oct(Params_group(params), mpk,
                     POINT_CONVERSION_COMPRESSED, mpk_buf, 33,
                     Params_ctx(params));
  EC_POINT_point2oct(Params_group(params), pk_vrf,
                     POINT_CONVERSION_COMPRESSED, pk_vrf_buf, 33,
                     Params_ctx(params));
  fwrite(mpk_buf, 33, 1, pk_file);
  fwrite(pk_vrf_buf, 33, 1, pk_file);
  fclose(pk_file);*/

  /* Write map of key handles to public keys. */
  FILE *kh_file = fopen(KH_FILE, "w");
  uint8_t pt[33];
  for (map<KeyHandle, EC_POINT*>::iterator it = pk_map.begin();
       it != pk_map.end(); it++) {
    EC_POINT_point2oct(Params_group(params), it->second,
                       POINT_CONVERSION_COMPRESSED, pt, 33,
                       Params_ctx(params));
    fwrite(it->first.data, MAX_KH_SIZE, 1, kh_file);
    fwrite(pt, 33, 1, kh_file);
  }
  fclose(kh_file);

}

/* Read agent state from file, including root public keys and map of key handles
 * to public keys. Should be called when destroying an old agent. */
void Client::ReadFromStorage() {
  /* Read mpk and pk_vrf. */
/*  uint8_t mpk_buf[33];
  uint8_t pk_vrf_buf[33];
  FILE *pk_file = fopen(PK_FILE, "r");
  if (pk_file != NULL) {
    if (fread(mpk_buf, P256_SCALAR_SIZE + 1, 1, pk_file) != 1) {
      fprintf(stderr, "ERROR: can't read mpk from file\n");
    }
    if (fread(pk_vrf_buf, P256_SCALAR_SIZE + 1, 1, pk_file) != 1) {
      fprintf(stderr, "ERROR: can't read pk_vrf from file\n");
    }
    if ((EC_POINT_oct2point(Params_group(params), mpk, mpk_buf, 33,
                           Params_ctx(params)) != OKAY) ||
        (EC_POINT_oct2point(Params_group(params), pk_vrf, pk_vrf_buf, 33,
                          Params_ctx(params)) != OKAY)) {
      fprintf(stderr, "ERROR: public key in invalid format\n");
    }
    fclose(pk_file);
  }*/

  /* Read map of key handles to public keys. */
  FILE *kh_file = fopen(KH_FILE, "r");
  if (kh_file != NULL) {
    uint8_t pt_buf[33];
    uint8_t kh[MAX_KH_SIZE];
    EC_POINT *pt;
    while (fread(kh, MAX_KH_SIZE, 1, kh_file) == 1) {
      if (fread(pt_buf, 33, 1, kh_file) != 1) {
        fprintf(stderr, "ERROR: no corresponding pk for key handle");
      }
      pt = Params_point_new(params);
      if (EC_POINT_oct2point(Params_group(params), pt, pt_buf, 33,
                             Params_ctx(params)) != OKAY) {
        fprintf(stderr, "ERROR: public key in invalid format\n");
      }
      pk_map[KeyHandle(kh)] = pt;
    }
    fclose(kh_file);
  }

}

/* Run registration with origin specified by app_id. Returns sum of lengths of
 * attestation certificate and batch signature. */
int Client::Register(const uint8_t *app_id, const uint8_t *challenge,
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
  BIGNUM *x;
  BIGNUM *y;
  uint8_t signed_data[1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE +
      P256_POINT_SIZE];
  EVP_PKEY *anon_pkey;
  string str;
  fprintf(stderr, "det2f: before params\n");
  Params params = Params_new(P256);
  fprintf(stderr, "det2f: after params\n");

  CHECK_A(cert = X509_new());
  CHECK_A(anon_key = EC_KEY_new());
  CHECK_A(evpctx = EVP_MD_CTX_create());
  CHECK_A(r = BN_new());
  CHECK_A(s = BN_new());
  CHECK_A(x = BN_new());
  CHECK_A(y = BN_new());
  CHECK_A(anon_pkey = EVP_PKEY_new());
  pk = Params_point_new(params);

  fprintf(stderr, "det2f: going to generate key handle\n");

  /* Generate key handle. */
  generate_key_handle(app_id, U2F_APPID_SIZE, key_handle_out, MAX_KH_SIZE);

  fprintf(stderr, "det2f: generated key handle\n");

  /* Output result. */
  // TODO choose keypair
  Params_rand_point(params, pk);
  EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
  BN_bn2bin(x, pk_out->x);
  BN_bn2bin(y, pk_out->y);
  pk_out->format = UNCOMPRESSED_POINT;

  fprintf(stderr, "det2f: chose pub key\n");

  /* Randomly choose key for attestation. */
  CHECK_C (EC_KEY_set_group(anon_key, Params_group(params)));
  CHECK_C (EC_KEY_generate_key(anon_key));

  fprintf(stderr, "det2f: chose attestation key\n");

  /* Generate self-signed cert. */
  cert_len = generate_cert(params, anon_key, cert_sig_out);

  fprintf(stderr, "det2f: self signed cert\n");

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

  fprintf(stderr, "det2f: did sig\n");

cleanup:
  if (rv == ERROR && pk) EC_POINT_clear_free(pk);
  if (cert) X509_free(cert);
  if (anon_pkey) EVP_PKEY_free(anon_pkey);
  if (evpctx) EVP_MD_CTX_destroy(evpctx);
  return cert_len + sig_len;
}

/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Returns length of signature. */
int Client::Authenticate(const uint8_t *app_id, const uint8_t *challenge,
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
  Params params = Params_new(P256);

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

