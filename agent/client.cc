
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>
#include <map>

#include <iostream>
#include <iomanip>
#include "json.hpp"
#include <string>

#include <grpcpp/grpcpp.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>

#include <emp-tool/emp-tool.h>

//#include "agent.h"
#include "../crypto/common.h"
#include "../crypto/sigs.h"
#include "base64.h"
#include "u2f.h"
#include "client.h"
#include "x509.h"
#include "asn1.h"
#include "../zkboo/src/proof.h"
#include "../zkboo/src/prover.h"
#include "../zkboo/src/prover_sys.h"
#include "../zkboo/src/verifier.h"
#include "../network/log.grpc.pb.h"
#include "../network/log.pb.h"

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
#define KH_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/kh_file.txt"
#define SK_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/sk_file.txt"

using namespace std;
using namespace nlohmann;
using namespace emp;
using namespace grpc;

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
  //memcpy(key_handle, app_id, app_id_len);
  //CHECK_C (RAND_bytes(key_handle + app_id_len, key_handle_len - app_id_len));
  CHECK_C (RAND_bytes(key_handle, key_handle_len));

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
    logAddr = "127.0.0.1:12345";
    //logAddr = "3.134.86.85:12345";
}

/* Write agent state to file, including root public keys and map of key handles
 * to public keys. Should be called when creating a new agent. */
// TODO: error checking
void Client::WriteToStorage() {
  /* Write map of key handles to public keys. */
  FILE *kh_file = fopen(KH_FILE, "w");
  uint8_t pt[33];
  for (map<string, EC_POINT*>::iterator it = pk_map.begin();
       it != pk_map.end(); it++) {
    EC_POINT_point2oct(Params_group(params), it->second,
                       POINT_CONVERSION_COMPRESSED, pt, 33,
                       Params_ctx(params));
    fwrite(it->first.c_str(), MAX_KH_SIZE, 1, kh_file);
    fwrite(pt, 33, 1, kh_file);
  }
  fclose(kh_file);

  FILE *sk_file = fopen(SK_FILE, "w");
  uint8_t buf[32];
  for (map<string, BIGNUM*>::iterator it = sk_map.begin();
       it != sk_map.end(); it++) {
    BN_bn2bin(it->second, buf);
    fwrite(it->first.c_str(), MAX_KH_SIZE, 1, sk_file);
    fwrite(buf, 32, 1, sk_file);
  }
  fclose(sk_file);
  fprintf(stderr, "det2f: WROTE TO STORAGE\n");

}

/* Read agent state from file, including root public keys and map of key handles
 * to public keys. Should be called when destroying an old agent. */
void Client::ReadFromStorage() {
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
      pk_map[string((const char *)kh, MAX_KH_SIZE)] = pt;
    }
    fclose(kh_file);
  }

  FILE *sk_file = fopen(SK_FILE, "r");
  if (sk_file != NULL) {
    uint8_t buf[32];
    uint8_t kh[MAX_KH_SIZE];
    BIGNUM *bn;
    while (fread(kh, MAX_KH_SIZE, 1, sk_file) == 1) {
      if (fread(buf, 32, 1, kh_file) != 1) {
        fprintf(stderr, "ERROR: no corresponding pk for key handle");
      }
      bn = BN_new();
      BN_bin2bn(buf, 32, bn);
      sk_map[string((const char *)kh, MAX_KH_SIZE)] = bn;
    }
    fclose(sk_file);
  }

}

// TODO rejection sampling
void Client::GetPreprocessValue(Params &p, EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret) {
    uint8_t pt[16];
    uint8_t out[16];
    int len;
    memset(pt, 0, 16);
    memcpy(pt, (uint8_t *)&ctr, sizeof(uint64_t));
    EVP_EncryptUpdate(ctx, out, &len, pt, 16);
    BN_bin2bn(out, len, ret);
    BN_mod(ret, ret, Params_order(p), bn_ctx);
}

void Client::GetPreprocessValue(Params &p, uint8_t *seed, uint64_t ctr, BIGNUM *ret) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t iv[16];
    memset(iv, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, iv);
    GetPreprocessValue(p, ctx, bn_ctx, ctr, ret);
}

void Client::GetPreprocessValueSet(Params &p, EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c) {
    uint64_t ctr = i * 4;
    GetPreprocessValue(p, ctx, bn_ctx, ctr, r);
    GetPreprocessValue(p, ctx, bn_ctx, ctr + 1, a);
    GetPreprocessValue(p, ctx, bn_ctx, ctr + 2, b);
    GetPreprocessValue(p, ctx, bn_ctx, ctr + 3, c);
}

void Client::GetPreprocessValueSet(Params &p, uint8_t *seed, uint64_t i, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c) {
    uint64_t ctr = i * 4;
    GetPreprocessValue(p, seed, ctr, r);
    GetPreprocessValue(p, seed, ctr + 1, a);
    GetPreprocessValue(p, seed, ctr + 2, b);
    GetPreprocessValue(p, seed, ctr + 3, c);
}

// TODO compress r1 or r2 with PRG
void Client::Preprocess(vector<Hint> &logHints) {
    BIGNUM *r = NULL;
    BIGNUM *r1 = NULL;
    BIGNUM *r2 = NULL;
    BIGNUM *a1 = NULL;
    BIGNUM *b1 = NULL;
    BIGNUM *c1 = NULL;
    BIGNUM *a2 = NULL;
    BIGNUM *b2 = NULL;
    BIGNUM *c2 = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *c = NULL;
    EC_POINT *R = NULL;
    BN_CTX *ctx = NULL;
    EVP_CIPHER_CTX *evp_ctx = NULL;
    int rv;
    uint8_t iv[16];

    CHECK_A (r = BN_new());
    CHECK_A (r1 = BN_new());
    CHECK_A (r2 = BN_new());
    CHECK_A (a1 = BN_new());
    CHECK_A (b1 = BN_new());
    CHECK_A (c1 = BN_new());
    CHECK_A (a2 = BN_new());
    CHECK_A (b2 = BN_new());
    CHECK_A (c2 = BN_new());
    CHECK_A (a = BN_new());
    CHECK_A (b = BN_new());
    CHECK_A (c = BN_new());
    CHECK_A (R = EC_POINT_new(Params_group(params)));
    CHECK_A (ctx = BN_CTX_new());
    CHECK_A (evp_ctx = EVP_CIPHER_CTX_new());

    memset(iv, 0, 16);
    RAND_bytes(seed, 16);
    EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ctr(), NULL, seed, iv);

    for (int i = 0; i < NUM_AUTHS; i++) {
        GetPreprocessValueSet(params, evp_ctx, ctx, i, r1, a1, b1, c1);
        CHECK_C (Params_rand_exponent(params, r2));
        CHECK_C (BN_mod_add(r, r1, r2, Params_order(params), ctx));
        CHECK_C (Params_exp(params, R, r));

        CHECK_C (Params_rand_exponent(params, a2));
        CHECK_C (Params_rand_exponent(params, b2));
        CHECK_C (BN_mod_add(a, a1, a2, Params_order(params), ctx));
        CHECK_C (BN_mod_add(b, b1, b2, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(c, a, b, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(c2, c, c1, Params_order(params), ctx));

        clientHints.push_back(ShortHint(R));
        logHints.push_back(Hint(r2, R, a2, b2, c2));
    }

cleanup:
    if (r) BN_free(r);
    if (r1) BN_free(r1);
    if (r2) BN_free(r2);
    if (a) BN_free(a);
    if (b) BN_free(b);
    if (c) BN_free(c);
    if (R) EC_POINT_free(R);
    if (ctx) BN_CTX_free(ctx);
}

int Client::Initialize() {
    InitRequest req;
    InitResponse resp;
    ClientContext client_ctx;
    unique_ptr<Log::Stub> stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
    uint8_t comm_in[64];
    vector<Hint> logHints;
    
    uint8_t *buf = (uint8_t *)malloc(33);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    RAND_bytes(enc_key, 16);
    RAND_bytes(r_open, 16);

    memset(comm_in, 0, 64);
    memcpy(comm_in, enc_key, 16);
    memcpy(comm_in + 16, r_open, 16);
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, comm_in, 32);
    EVP_DigestFinal(mdctx, enc_key_comm, NULL);

    Preprocess(logHints);

    for (int i = 0; i < NUM_AUTHS; i++) {
        HintMsg *h = req.add_hints();
        BN_bn2bin(logHints[i].r, buf);
        h->set_r(buf, BN_num_bytes(logHints[i].r));
        BN_bn2bin(logHints[i].a, buf);
        h->set_a(buf, BN_num_bytes(logHints[i].a));
        BN_bn2bin(logHints[i].b, buf);
        h->set_b(buf, BN_num_bytes(logHints[i].b));
        BN_bn2bin(logHints[i].c, buf);
        h->set_c(buf, BN_num_bytes(logHints[i].c));
        EC_POINT_point2oct(Params_group(params), logHints[i].R,
                       POINT_CONVERSION_COMPRESSED, buf, 33,
                       Params_ctx(params));
        h->set_g_r(buf, 33);
    }

    req.set_key_comm(enc_key_comm, 32);
    stub->SendInit(&client_ctx, req, &resp);
    logPk = Params_point_new(params);
    EC_POINT_oct2point(Params_group(params), logPk, (uint8_t *)resp.pk().c_str(), 33,
                           Params_ctx(params));
 
}

/* Run registration with origin specified by app_id. Returns sum of lengths of
 * attestation certificate and batch signature. */
int Client::Register(uint8_t *app_id, uint8_t *challenge,
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
  BIGNUM *exp;
  uint8_t signed_data[1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE +
      P256_POINT_SIZE];
  EVP_PKEY *anon_pkey;
  string str;
  BN_CTX *ctx;
  unique_ptr<Log::Stub> stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
  RegRequest req;
  RegResponse resp;
  ClientContext client_ctx;
  vector<Hint> logHints;

  CHECK_A(cert = X509_new());
  CHECK_A(anon_key = EC_KEY_new());
  CHECK_A(evpctx = EVP_MD_CTX_create());
  CHECK_A(r = BN_new());
  CHECK_A(s = BN_new());
  CHECK_A(x = BN_new());
  CHECK_A(y = BN_new());
  CHECK_A(exp = BN_new());
  CHECK_A(ctx = BN_CTX_new());
  CHECK_A(anon_pkey = EVP_PKEY_new());
  pk = Params_point_new(params);

  fprintf(stderr, "det2f: going to generate key handle\n");

  /* Generate key handle. */
  generate_key_handle(app_id, U2F_APPID_SIZE, key_handle_out, MAX_KH_SIZE);

  fprintf(stderr, "det2f: generated key handle\n");

  /* Output result. */
  
/*  Params_rand_point_exp(params, pk, exp);
  pk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = pk;
  sk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = exp;
  EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
  BN_bn2bin(x, pk_out->x);
  BN_bn2bin(y, pk_out->y);
  pk_out->format = UNCOMPRESSED_POINT;*/

  stub->SendReg(&client_ctx, req, &resp);
  memcpy(pk_out->x, resp.pk_x().c_str(), P256_SCALAR_SIZE);
  memcpy(pk_out->y, resp.pk_y().c_str(), P256_SCALAR_SIZE);
  fprintf(stderr, "det2f: x = ");
  for (int i = 0; i < P256_SCALAR_SIZE; i++) {
    fprintf(stderr, "%x", pk_out->x[i]);
  }
  fprintf(stderr, "\n");
  fprintf(stderr, "det2f: y = ");
  for (int i = 0; i < P256_SCALAR_SIZE; i++) {
    fprintf(stderr, "%x", pk_out->y[i]);
  }
  fprintf(stderr, "\n");
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
int Client::Authenticate(uint8_t *app_id, int app_id_len, uint8_t *challenge,
                 uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool checkOnly) {
  int rv = ERROR;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  EVP_MD_CTX *mdctx;
  EVP_MD_CTX *mdctx2;
  EVP_MD_CTX *mdctx3;
  uint8_t message[SHA256_DIGEST_LENGTH];
  uint8_t app_id_digest[SHA256_DIGEST_LENGTH];
  ECDSA_SIG *sig = NULL;
  unsigned int sig_len = 0;
  //size_t sig_len_sizet = 0;
  //uint8_t flags = 5;
  uint8_t flags = 0x01;
  uint8_t ctr[4];
  EC_KEY *key;
  memset(ctr, 0, 4 * sizeof(uint8_t));
  uint32_t c = 11;
  ctr[0] = 0xFF & c >> 24;
  ctr[1] = 0xFF & c >> 16;
  ctr[2] = 0xFF & c >> 8;
  ctr[3] = 0xFF & c;
  BN_CTX *ctx;
  int message_buf_len = SHA256_DIGEST_LENGTH + sizeof(flags) + 4 * sizeof(uint8_t) + U2F_NONCE_SIZE;
  uint8_t message_buf[SHA256_DIGEST_LENGTH + sizeof(flags) + 4 * sizeof(uint8_t) + U2F_NONCE_SIZE];
  uint8_t len_byte;
  uint8_t sig_out2[MAX_ECDSA_SIG_SIZE];
  EVP_PKEY *pkey;
  //uint8_t r_open[16];
  //uint8_t enc_key_comm[32];
  uint8_t hash_out[32];
  uint8_t comm_in[64];
  uint8_t ct[SHA256_DIGEST_LENGTH];
  __m128i iv = makeBlock(0,0);
  __m128i enc_key_raw = makeBlock(0,0);
  //uint8_t enc_key[16];
  Proof proof;
  int numRands = 116916;
  uint8_t *proof_buf;
  int proof_buf_len;
  uint8_t iv_raw[16];

  unique_ptr<Log::Stub> stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
  AuthRequest req;
  AuthResponse resp;
  ClientContext client_ctx;

  CHECK_A (r = BN_new());
  CHECK_A (s = BN_new());
  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (mdctx2 = EVP_MD_CTX_create());
  CHECK_A (mdctx3 = EVP_MD_CTX_create());
  CHECK_A (ctx = BN_CTX_new());
  CHECK_A (sig = ECDSA_SIG_new());
  CHECK_A (key = EC_KEY_new());
  pkey = EVP_PKEY_new();

  fprintf(stderr, "det2f: going to hash app id\n");
  fprintf(stderr, "det2f: hashed app id\n");

  /* Compute signed message: hash of appId, user presence, counter, and
   * challenge. */
  memcpy(message_buf, app_id, SHA256_DIGEST_LENGTH);
  memcpy(message_buf + SHA256_DIGEST_LENGTH, &flags, sizeof(flags));
  memcpy(message_buf + SHA256_DIGEST_LENGTH + sizeof(flags), ctr, 4 * sizeof(uint8_t));
  memcpy(message_buf + SHA256_DIGEST_LENGTH + sizeof(flags) + 4 * sizeof(uint8_t), challenge, U2F_NONCE_SIZE);
  fprintf(stderr, "det2f: AUTH DATA: ");
  for (int i = 0; i < message_buf_len; i++) {
    fprintf(stderr, "%d ", message_buf[i]);
  }
  fprintf(stderr, "\n");

  EVP_DigestInit_ex(mdctx2, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx2, message_buf, message_buf_len);
  EVP_DigestFinal(mdctx2, hash_out, NULL);

  memset(enc_key, 0, 16);
  aes_128_ctr(enc_key_raw, iv, app_id, ct, SHA256_DIGEST_LENGTH, 0); 

  memset(comm_in, 0, 512 / 8);
  memcpy(comm_in, enc_key, 128 / 8);
  memcpy(comm_in + (128 / 8), r_open, 128 / 8);
  EVP_DigestInit_ex(mdctx3, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx3, comm_in, 512/8);
  EVP_DigestFinal(mdctx3, enc_key_comm, NULL);

  fprintf(stderr, "det2f: proving circuit\n");
  ProveCtCircuit(app_id, SHA256_DIGEST_LENGTH * 8, message_buf, message_buf_len * 8, hash_out, ct, enc_key, enc_key_comm, r_open, iv, numRands, proof);

  proof_buf = proof.Serialize(&proof_buf_len);
  req.set_proof(proof_buf, proof_buf_len);
  fprintf(stderr, "det2f: message_buf_len = %d\n", message_buf_len);
  req.set_challenge(message_buf, message_buf_len);
  req.set_ct(ct, SHA256_DIGEST_LENGTH);
  // TODO real IV
  memset(iv_raw, 0, 16);
  req.set_iv(iv_raw, 16);
  stub->SendAuth(&client_ctx, req, &resp);
  memset(sig_out, 0, MAX_ECDSA_SIG_SIZE);
  sig_len = resp.sig().size();
  fprintf(stderr, "sig_len = %d\n", sig_len);
  memcpy(sig_out, resp.sig().c_str(), sig_len);

/*  fprintf(stderr, "det2f: proved circuit\n");
  //VerifyCtCircuit(proof, iv, SHA256_DIGEST_LENGTH * 8, message_buf_len * 8);
  fprintf(stderr, "det2f: verified circuit\n");

  // TODO: Sign message and produce r,s
  fprintf(stderr, "det2f: signing with %s\n", BN_bn2hex(sk_map[string((const char *)key_handle, MAX_KH_SIZE)]));
  EC_KEY_set_group(key, params->group);
  EC_KEY_set_private_key(key, sk_map[string((const char *)key_handle, MAX_KH_SIZE)]);
  EC_KEY_set_public_key(key, pk_map[string((const char *)key_handle, MAX_KH_SIZE)]);
  memset(sig_out, 0, MAX_ECDSA_SIG_SIZE);
  fprintf(stderr, "det2f: going to sign\n");
  EVP_PKEY_assign_EC_KEY(pkey, key);
  EVP_MD_CTX_init(mdctx);
  EVP_SignInit(mdctx, EVP_sha256());
  EVP_SignUpdate(mdctx, message_buf, message_buf_len);
  EVP_SignFinal(mdctx, sig_out, &sig_len, pkey);
  fprintf(stderr, "det2f: just signed\n");
  fprintf(stderr, "det2f: PK SIGNED WITH %s\n", EC_POINT_point2hex(Params_group(params), pk_map[string((const char *)key_handle, MAX_KH_SIZE)], POINT_CONVERSION_UNCOMPRESSED, ctx));*/
  //sig_len = sig_len_sizet;
  //sig = ECDSA_do_sign(message,  SHA256_DIGEST_LENGTH, key);
/*  sig = ECDSA_do_sign(message_buf,  message_buf_len, key);
  r = (BIGNUM *)ECDSA_SIG_get0_r(sig);
  s = (BIGNUM *)ECDSA_SIG_get0_s(sig);*/
  //ECDSA_sign(0, message_buf,  message_buf_len, sig_out2, &sig_len, key);
  //ECDSA_sign(0, message,  SHA256_DIGEST_LENGTH, sig_out, &sig_len, key);
  /*fprintf(stderr, "det2f: sig ");
  for (int i = 0; i < MAX_ECDSA_SIG_SIZE; i++) {
    fprintf(stderr, "%02x", sig_out2[i]);
  }
  fprintf(stderr, "\n");*/

  /* Output signature. */
  /*asn1_sigp(sig_out, r, s);
  len_byte = sig_out[1];
  sig_len = len_byte + 1;*/
/*  fprintf(stderr, "det2f: ECDSA_SIG ");
  for (int i = 0; i < sig_len; i++) {
    fprintf(stderr, "%02x", sig_out2[i]);
  }*/
  fprintf(stderr, "\n");
  fprintf(stderr, "det2f: manually encoded sig ");
  for (int i = 0; i < MAX_ECDSA_SIG_SIZE; i++) {
    fprintf(stderr, "%02x", sig_out[i]);
  }
  fprintf(stderr, "\n");
/*  if (memcmp(sig_out, sig_out2, sig_len) != 0) {
    fprintf(stderr, "det2f: NOT SAME\n");
  }*/

  /* Output message from device. */
  *flags_out = flags;
  *ctr_out = c;
  //memcpy(ctr_out, ctr, sizeof(uint32_t));
  fprintf(stderr, "det2f: counter out = %d\n", *ctr_out);

cleanup:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  fprintf(stderr, "det2f: sig_len = %d vs %d\n", sig_len, MAX_ECDSA_SIG_SIZE);
  return rv == OKAY ? sig_len : ERROR;
}

