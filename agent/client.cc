
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
#include <thread>

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
#include "../zkboo/utils/timer.h"
#include "../zkboo/utils/colors.h"
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
#define KH_FILE "/home/ec2-user/out/kh_file.txt"
//#define KH_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/kh_file.txt"
#define SK_FILE "/home/ec2-user/out/sk_file.txt"
//#define SK_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/sk_file.txt"
#define MASTER_FILE "/home/ec2-user/out/master_file.txt"
//#define MASTER_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/master_file.txt"
#define HINT_FILE "/home/ec2-user/out/hint_file.txt"
//#define HINT_FILE "/Users/emmadauterman/Projects/zkboo-r1cs/agent/out/hint_file.txt"

#define NUM_ROUNDS 5

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
    logAddr = "13.59.107.196:12345";
    //logAddr = "127.0.0.1:12345";
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

  FILE *hint_file = fopen(HINT_FILE, "w");
  for (int i = 0; i < clientHints.size(); i++) {
      BN_bn2bin(clientHints[i].xcoord, buf);
      fwrite(buf, 32, 1, hint_file);
      BN_bn2bin(clientHints[i].auth_xcoord, buf);
      fwrite(buf, 32, 1, hint_file);
  }
  fclose(hint_file);

  FILE *master_file = fopen(MASTER_FILE, "w");
  EC_POINT_point2oct(Params_group(params), logPk,
                       POINT_CONVERSION_COMPRESSED, pt, 33,
                       Params_ctx(params));
  fwrite(pt, 33, 1, hint_file);
  fwrite(enc_key, 16, 1, master_file);
  fwrite(r_open, 16, 1, master_file);
  fwrite(enc_key_comm, 32, 1, master_file);
  fwrite((uint8_t *)&auth_ctr, sizeof(uint32_t), 1, master_file);
  fwrite(seed, 16, 1, master_file);
  fclose(master_file);
 
  //fprintf(stderr, "det2f: auth ctr=%d\n", auth_ctr); 
  //fprintf(stderr, "det2f: WROTE TO STORAGE\n");

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

  FILE *hint_file = fopen(HINT_FILE, "r");
  uint8_t long_buf[64];
  if (hint_file != NULL) {
    BIGNUM *xcoord, *auth_xcoord;
    while (fread(long_buf, 64, 1, hint_file) == 1) {
      xcoord = BN_new();
      auth_xcoord = BN_new();
      BN_bin2bn(long_buf, 32, xcoord);
      BN_bin2bn(long_buf + 32, 32, auth_xcoord);
      clientHints.push_back(ShortHint(xcoord, auth_xcoord));
    }
    fclose(kh_file);
  }

  uint8_t pt_buf[33];
  FILE *master_file = fopen(MASTER_FILE, "r");
  logPk = Params_point_new(params);
  if (fread(pt_buf, 33, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: public key not in file\n");
  }
  if (EC_POINT_oct2point(Params_group(params), logPk, pt_buf, 33,
                         Params_ctx(params)) != OKAY) {
       fprintf(stderr, "ERROR: public key in invalid format\n");
  }
  if (fread(enc_key, 16, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: enc_key not in file\n");
  }
  if (fread(r_open, 16, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: r_open not in file\n");
  }
  if (fread(enc_key_comm, 32, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: commitment not in file\n");
  }
  if (fread((uint8_t *)&auth_ctr, 4, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: auth ctr not in file\n");
  }
  if (fread((uint8_t *)&seed, 16, 1, master_file) != 1) {
    fprintf(stderr, "ERROR: seed not in file\n");
  }
  //fprintf(stderr, "det2f: auth ctr=%d\n", auth_ctr); 
  fclose(master_file);
 
}

// TODO 32 bytes and mod order
void Client::GetPreprocessValue(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t ctr, BIGNUM *ret) {
    uint8_t pt[16];
    uint8_t out[16];
    int len;
    memset(pt, 0, 16);
    memcpy(pt, (uint8_t *)&ctr, sizeof(uint64_t));
    EVP_EncryptUpdate(ctx, out, &len, pt, 16);
    BN_bin2bn(out, len, ret);
    BN_mod(ret, ret, Params_order(params), bn_ctx);
}

void Client::GetPreprocessValue(uint64_t ctr, BIGNUM *ret) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    uint8_t iv[16];
    memset(iv, 0, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, iv);
    GetPreprocessValue(ctx, bn_ctx, ctr, ret);
}

void Client::GetPreprocessValueSet(EVP_CIPHER_CTX *ctx, BN_CTX *bn_ctx, uint64_t i, BIGNUM *r, BIGNUM *auth_r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *f, BIGNUM *g, BIGNUM *h, BIGNUM *alpha) {
    uint64_t ctr = i * 9;
    GetPreprocessValue(ctx, bn_ctx, ctr, r);
    GetPreprocessValue(ctx, bn_ctx, ctr + 1, auth_r);
    GetPreprocessValue(ctx, bn_ctx, ctr + 2, a);
    GetPreprocessValue(ctx, bn_ctx, ctr + 3, b);
    GetPreprocessValue(ctx, bn_ctx, ctr + 4, c);
    GetPreprocessValue(ctx, bn_ctx, ctr + 5, f);
    GetPreprocessValue(ctx, bn_ctx, ctr + 6, g);
    GetPreprocessValue(ctx, bn_ctx, ctr + 7, h);
    GetPreprocessValue(ctx, bn_ctx, ctr + 8, alpha);
}

void Client::GetPreprocessValueSet(uint64_t i, BIGNUM *r, BIGNUM *auth_r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *f, BIGNUM *g, BIGNUM *h, BIGNUM *alpha) {
    uint64_t ctr = i * 9;
    GetPreprocessValue(ctr, r);
    GetPreprocessValue(ctr + 1, auth_r);
    GetPreprocessValue(ctr + 2, a);
    GetPreprocessValue(ctr + 3, b);
    GetPreprocessValue(ctr + 4, c);
    GetPreprocessValue(ctr + 5, f);
    GetPreprocessValue(ctr + 6, g);
    GetPreprocessValue(ctr + 7, h);
    GetPreprocessValue(ctr + 8, alpha);
}

// TODO compress r1 or r2 with PRG
void Client::Preprocess(vector<Hint> &logHints) {
    BIGNUM *r = NULL;
    BIGNUM *r_inv = NULL;
    BIGNUM *r1 = NULL;
    BIGNUM *r2 = NULL;
    BIGNUM *a1, *b1, *c1;
    BIGNUM *a2, *b2, *c2;
    BIGNUM *a, *b, *c;
    BIGNUM *f1, *g1, *h1;
    BIGNUM *f2, *g2, *h2;
    BIGNUM *f, *g, *h;
    BIGNUM *alpha1, *alpha2, *alpha;
    BIGNUM *auth_r1, *auth_r2, *auth_r;
    BIGNUM *xcoord, *ycoord, *auth_xcoord;
    BIGNUM *zero = NULL;
    BIGNUM *neg_one = NULL;
    EC_POINT *R = NULL;
    BN_CTX *ctx = NULL;
    EVP_CIPHER_CTX *evp_ctx = NULL;
    int rv;
    uint8_t iv[16];

    CHECK_A (ctx = BN_CTX_new());
    CHECK_A (evp_ctx = EVP_CIPHER_CTX_new());

    memset(iv, 0, 16);
    RAND_bytes(seed, 16);
    EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ctr(), NULL, seed, iv);
/*
    CHECK_A (zero = BN_new());
    CHECK_A (neg_one = BN_new());
    BN_zero(zero);
    CHECK_C (BN_mod_sub(neg_one, zero, BN_value_one(), Params_order(params), ctx));
*/
    for (int i = 0; i < NUM_AUTHS; i++) {

        CHECK_A (r = BN_new());
        //CHECK_A (r_inv = BN_new());
        CHECK_A (r1 = BN_new());
        CHECK_A (auth_r1 = BN_new());
        CHECK_A (auth_r2 = BN_new());
        CHECK_A (auth_r = BN_new());
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
        CHECK_A (f1 = BN_new());
        CHECK_A (g1 = BN_new());
        CHECK_A (h1 = BN_new());
        CHECK_A (f2 = BN_new());
        CHECK_A (g2 = BN_new());
        CHECK_A (h2 = BN_new());
        CHECK_A (f = BN_new());
        CHECK_A (g = BN_new());
        CHECK_A (h = BN_new());
        CHECK_A (alpha1 = BN_new());
        CHECK_A (alpha2 = BN_new());
        CHECK_A (alpha = BN_new());
        CHECK_A (xcoord = BN_new());
        CHECK_A (ycoord = BN_new());
        CHECK_A (auth_xcoord = BN_new());
        CHECK_A (R = EC_POINT_new(Params_group(params)));

        GetPreprocessValueSet(i, r1, auth_r1, a1, b1, c1, f1, g1, h1, alpha1);
        //GetPreprocessValueSet(evp_ctx, ctx, i, r1, a1, b1, c1);
        //CHECK_C (Params_rand_exponent(params, r2));
        //CHECK_C (BN_mod_add(r, r1, r2, Params_order(params), ctx));
        CHECK_C (Params_rand_exponent(params, r));
        r_inv = BN_mod_inverse(NULL, r, Params_order(params), ctx);
        //CHECK_C (BN_mod_exp(r_inv, r, neg_one, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(r2, r_inv, r1, Params_order(params), ctx));
        CHECK_C (Params_exp(params, R, r));

        CHECK_C (Params_rand_exponent(params, a2));
        CHECK_C (Params_rand_exponent(params, b2));
        CHECK_C (BN_mod_add(a, a1, a2, Params_order(params), ctx));
        CHECK_C (BN_mod_add(b, b1, b2, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(c, a, b, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(c2, c, c1, Params_order(params), ctx));

        CHECK_C (Params_rand_exponent(params, alpha2));
        CHECK_C (BN_mod_add(alpha, alpha1, alpha2, Params_order(params), ctx));

        CHECK_C (BN_mod_mul(f, a, alpha, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(g, b, alpha, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(h, c, alpha, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(f2, f, f1, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(g2, g, g1, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(h2, h, h1, Params_order(params), ctx));

        EC_POINT_get_affine_coordinates_GFp(params->group, R, xcoord, ycoord, NULL);
        CHECK_C (BN_mod(xcoord, xcoord, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(auth_xcoord, xcoord, alpha, Params_order(params), ctx));
        CHECK_C (BN_mod_mul(auth_r, r_inv, alpha, Params_order(params), ctx));
        CHECK_C (BN_mod_sub(auth_r2, auth_r, auth_r1, Params_order(params), ctx));


        
 /*       BN_zero(a2);
        BN_zero(b2);
        BN_zero(r2);
        r = BN_mod_inverse(NULL ,r1, Params_order(params), ctx);
        BN_mod_mul(c, a1, b1, Params_order(params), ctx);
        BN_mod_sub(c2, c, c1, Params_order(params), ctx);
        Params_exp(params, R, r);
        printf("r = %s\n", BN_bn2hex(r));
        printf("r1 = %s\n", BN_bn2hex(r1));
        printf("c2 = %s\n", BN_bn2hex(c2));*/

        clientHints.push_back(ShortHint(xcoord, auth_xcoord));
        logHints.push_back(Hint(xcoord, auth_xcoord, r2, auth_r2, a2, b2, c2, f2, g2, h2, alpha2));
        BN_free(r);
        BN_free(r1);
        BN_free(a1);
        BN_free(a);
        BN_free(b1);
        BN_free(b);
        BN_free(c1);
        BN_free(c);
    }

cleanup:
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

    //fprintf(stderr, "det2f: going to do preprocessing\n");
    Preprocess(logHints);
    //fprintf(stderr, "det2f: done with preprocessing\n");

    for (int i = 0; i < NUM_AUTHS; i++) {
        HintMsg *h = req.add_hints();
        BN_bn2bin(logHints[i].xcoord, buf);
        h->set_xcoord(buf, BN_num_bytes(logHints[i].xcoord));
        BN_bn2bin(logHints[i].auth_xcoord, buf);
        h->set_auth_xcoord(buf, BN_num_bytes(logHints[i].auth_xcoord));
        BN_bn2bin(logHints[i].r, buf);
        h->set_r(buf, BN_num_bytes(logHints[i].r));
        BN_bn2bin(logHints[i].auth_r, buf);
        h->set_auth_r(buf, BN_num_bytes(logHints[i].auth_r));
        BN_bn2bin(logHints[i].a, buf);
        h->set_a(buf, BN_num_bytes(logHints[i].a));
        BN_bn2bin(logHints[i].b, buf);
        h->set_b(buf, BN_num_bytes(logHints[i].b));
        BN_bn2bin(logHints[i].c, buf);
        h->set_c(buf, BN_num_bytes(logHints[i].c));
        BN_bn2bin(logHints[i].f, buf);
        h->set_f(buf, BN_num_bytes(logHints[i].f));
        BN_bn2bin(logHints[i].g, buf);
        h->set_g(buf, BN_num_bytes(logHints[i].g));
        BN_bn2bin(logHints[i].h, buf);
        h->set_h(buf, BN_num_bytes(logHints[i].h));
        BN_bn2bin(logHints[i].alpha, buf);
        h->set_alpha(buf, BN_num_bytes(logHints[i].alpha));
    }

    req.set_key_comm(enc_key_comm, 32);
    stub->SendInit(&client_ctx, req, &resp);
    logPk = Params_point_new(params);
    EC_POINT_oct2point(Params_group(params), logPk, (uint8_t *)resp.pk().c_str(), 33,
                           Params_ctx(params));

    auth_ctr = 0;
 
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
  BIGNUM *sk;
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
  CHECK_A(sk = BN_new());
  CHECK_A(r = BN_new());
  CHECK_A(s = BN_new());
  CHECK_A(x = BN_new());
  CHECK_A(y = BN_new());
  CHECK_A(exp = BN_new());
  CHECK_A(ctx = BN_CTX_new());
  CHECK_A(anon_pkey = EVP_PKEY_new());
  pk = Params_point_new(params);

  //fprintf(stderr, "det2f: going to generate key handle\n");

  /* Generate key handle. */
  generate_key_handle(app_id, U2F_APPID_SIZE, key_handle_out, MAX_KH_SIZE);
  // NEW 2PC SIGS
  CHECK_C (Params_rand_exponent(params, sk));
  sk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = sk;
  CHECK_C (Params_exp(params, pk, sk));
  EC_POINT_add(Params_group(params), pk, pk, logPk, ctx);
  //fprintf(stderr, "det2f: sk = %s\n", BN_bn2hex(sk_map[string((const char *)key_handle_out, MAX_KH_SIZE)]));
  //CHECK_C (Params_exp_base(params, pk, logPk, sk));
  pk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = pk;
  EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
  BN_bn2bin(x, pk_out->x);
  BN_bn2bin(y, pk_out->y);
  pk_out->format = UNCOMPRESSED_POINT;


  //fprintf(stderr, "det2f: generated key handle\n");

  /* Output result. */

  
/*  Params_rand_point_exp(params, pk, exp);
  pk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = pk;
  sk_map[string((const char *)key_handle_out, MAX_KH_SIZE)] = exp;
  EC_POINT_get_affine_coordinates_GFp(params->group, pk, x, y, NULL);
  BN_bn2bin(x, pk_out->x);
  BN_bn2bin(y, pk_out->y);
  pk_out->format = UNCOMPRESSED_POINT;*/

/*  stub->SendReg(&client_ctx, req, &resp);
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
  pk_out->format = UNCOMPRESSED_POINT;*/

  //fprintf(stderr, "det2f: chose pub key\n");

  /* Randomly choose key for attestation. */
  CHECK_C (EC_KEY_set_group(anon_key, Params_group(params)));
  CHECK_C (EC_KEY_generate_key(anon_key));

  //fprintf(stderr, "det2f: chose attestation key\n");

  /* Generate self-signed cert. */
  cert_len = generate_cert(params, anon_key, cert_sig_out);

  //fprintf(stderr, "det2f: self signed cert\n");

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

  //fprintf(stderr, "det2f: did sig\n");

cleanup:
  if (rv == ERROR && pk) EC_POINT_clear_free(pk);
  if (cert) X509_free(cert);
  if (anon_pkey) EVP_PKEY_free(anon_pkey);
  if (evpctx) EVP_MD_CTX_destroy(evpctx);
  return cert_len + sig_len;
}

int Client::StartSigning(BIGNUM *msg_hash, BIGNUM *sk, BIGNUM *val, BIGNUM *r, BIGNUM *auth_r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, BIGNUM *e, BIGNUM *auth_d, BIGNUM *auth_e, BIGNUM *f, BIGNUM *g, BIGNUM *h, BIGNUM *alpha) {
  BN_CTX *ctx;
  int rv = OKAY;
  BIGNUM *auth_val = BN_new();
  BIGNUM *auth_hash = BN_new();

  ctx = BN_CTX_new();

  //fprintf(stderr, "det2f: x_coord = %s\n", BN_bn2hex(clientHints[auth_ctr].xcoord));
  BN_mod_mul(val, clientHints[auth_ctr].xcoord, sk, Params_order(params), ctx);
  BN_mod_add(val, val, msg_hash, Params_order(params), ctx);
  //fprintf(stderr, "det2f: COMPUTED VAL = %s\n", BN_bn2hex(val));
  //fprintf(stderr, "det2f: multiplying by r^-1 = %s\n", BN_bn2hex(r));

  BN_mod_mul(auth_val, clientHints[auth_ctr].auth_xcoord, sk, Params_order(params), ctx);
  BN_mod_mul(auth_hash, msg_hash, alpha, Params_order(params), ctx);
  BN_mod_add(auth_val, auth_val, auth_hash, Params_order(params), ctx);

  BN_mod_sub(d, r, a, Params_order(params), ctx);
  BN_mod_sub(e, val, b, Params_order(params), ctx);

  BN_mod_sub(auth_d, auth_r, f, Params_order(params), ctx);
  BN_mod_sub(auth_e, auth_val, g, Params_order(params), ctx);
  //fprintf(stderr, "det2f: finished start signing procedure\n");

cleanup:
  return rv;
}

int Client::FinishSigning(BIGNUM *val, BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, BIGNUM *e, BIGNUM *f, BIGNUM *g, BIGNUM *h, BIGNUM *alpha, BIGNUM *out, BIGNUM *auth_out) {
    BIGNUM *prod = NULL;
    BN_CTX *ctx;
    int rv = OKAY;

    prod = BN_new();
    ctx = BN_CTX_new();

    // de + d[b] + e[a] + [c]
    BN_mod_mul(out, d, e, Params_order(params), ctx);
    BN_mod_mul(prod, d, b, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, a, Params_order(params), ctx);
    BN_mod_add(out, out, prod, Params_order(params), ctx);
    BN_mod_add(out, out, c, Params_order(params), ctx);
    //fprintf(stderr, "det2f: * share of s = %s\n", BN_bn2hex(out));

    // authenticated value
    // de.\alpha + d[g] + e[f] + [h]
    BN_mod_mul(auth_out, d, e, Params_order(params), ctx);
    BN_mod_mul(auth_out, auth_out, alpha, Params_order(params), ctx);
    BN_mod_mul(prod, d, g, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_mul(prod, e, f, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, prod, Params_order(params), ctx);
    BN_mod_add(auth_out, auth_out, h, Params_order(params), ctx);

cleanup:
    return rv;
}

void Client::MakeCheckVal(BIGNUM *check, BIGNUM *val, BIGNUM *auth, BIGNUM *alpha) {
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_mul(check, alpha, val, Params_order(params), ctx);
    BN_mod_sub(check, auth, check, Params_order(params), ctx);
    BN_CTX_free(ctx);
}

void Client::ThresholdSign(BIGNUM *out, uint8_t *hash_out, BIGNUM *sk, AuthRequest &req) {
  BIGNUM *a, *b, *c;
  BIGNUM *d_client, *d_log, *auth_d, *d, *check_d;
  BIGNUM *e_client, *e_log, *auth_e, *e, *check_e;
  BIGNUM *f, *g, *h;
  BIGNUM *alpha;
  BIGNUM *auth_r, *r;
  BIGNUM *hash_bn = NULL;
  BIGNUM *out_client, *out_log, *auth_out_client;
  BIGNUM *val;
  BIGNUM *zero;
  unique_ptr<Log::Stub> stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
  AuthCheckRequest checkReq;
  AuthResponse resp;
  AuthCheckResponse checkResp;
  ClientContext client_ctx;
  ClientContext client_ctx2;
  uint8_t *d_buf, *e_buf, *check_d_buf, *check_e_buf;
  BN_CTX *ctx;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d_client = BN_new();
  d_log = BN_new();
  d = BN_new();
  e_client = BN_new();
  e_log = BN_new();
  e = BN_new();
  auth_d = BN_new();
  auth_e = BN_new();
  f = BN_new();
  g = BN_new();
  h = BN_new();
  alpha = BN_new();
  r = BN_new();
  auth_r = BN_new();
  out_log = BN_new();
  out_client = BN_new();
  auth_out_client = BN_new();
  hash_bn = BN_new();
  check_d = BN_new();
  check_e = BN_new();
  val = BN_new();
  ctx = BN_CTX_new();
  INIT_TIMER;
  START_TIMER;
 
 
  req.set_digest(hash_out, 32);
  GetPreprocessValueSet(auth_ctr, r, auth_r, a, b, c, f, g, h, alpha);
  BN_bin2bn(hash_out, 32, hash_bn);
  BN_mod(hash_bn, hash_bn, Params_order(params), ctx);
  StartSigning(hash_bn, sk, val, r, auth_r, a, b, c, d_client, e_client, auth_d, auth_e, f, g, h, alpha);
  d_buf = (uint8_t *)malloc(BN_num_bytes(d_client));
  e_buf = (uint8_t *)malloc(BN_num_bytes(e_client));
  BN_bn2bin(d_client, d_buf);
  BN_bn2bin(e_client, e_buf);
  req.set_d(d_buf, BN_num_bytes(d_client));
  req.set_e(e_buf, BN_num_bytes(e_client));
  STOP_TIMER("before send");

  stub->SendAuth(&client_ctx, req, &resp);

  BN_bin2bn((uint8_t *)resp.d().c_str(), resp.d().size(), d_log);
  BN_bin2bn((uint8_t *)resp.e().c_str(), resp.e().size(), e_log);
  BN_bin2bn((uint8_t *)resp.prod().c_str(), resp.prod().size(), out_log);
  
  BN_mod_add(d, d_client, d_log, Params_order(params), ctx);
  BN_mod_add(e, e_client, e_log, Params_order(params), ctx);

  FinishSigning(val, r, a, b, c, d, e, f, g, h, alpha, out_client, auth_out_client);

  MakeCheckVal(check_d, d, auth_d, alpha);
  MakeCheckVal(check_e, e, auth_e, alpha);

  check_d_buf = (uint8_t *)malloc(BN_num_bytes(check_d));
  check_e_buf = (uint8_t *)malloc(BN_num_bytes(check_e));
  BN_bn2bin(check_d, check_d_buf);
  BN_bn2bin(check_e, check_e_buf);
  checkReq.set_check_d(check_d_buf, BN_num_bytes(check_d));
  checkReq.set_check_e(check_e_buf, BN_num_bytes(check_e));
  checkReq.set_session_ctr(resp.session_ctr());

  stub->SendAuthCheck(&client_ctx2, checkReq, &checkResp);

  BN_bin2bn((uint8_t *)checkResp.out().c_str(), checkResp.out().size(), out_log);

  BN_mod_add(out, out_client, out_log, Params_order(params), ctx);
 
}


/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Returns length of signature. */
int Client::Authenticate(uint8_t *app_id, int app_id_len, uint8_t *challenge,
                 uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool noRegistration) {
  int rv = ERROR;
  INIT_TIMER;
  START_TIMER;
  
  BIGNUM *out = NULL;
  EC_POINT *R;
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
  uint32_t ctr32 = 11;
  ctr[0] = 0xFF & ctr32 >> 24;
  ctr[1] = 0xFF & ctr32 >> 16;
  ctr[2] = 0xFF & ctr32 >> 8;
  ctr[3] = 0xFF & ctr32;
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
  __m128i enc_key_128 = makeBlock(0,0);
  //uint8_t enc_key[16];
  Proof proof[NUM_ROUNDS];
  int numRands = 116916;
  uint8_t *proof_buf[NUM_ROUNDS];
  thread workers[NUM_ROUNDS];
  int proof_buf_len;
  uint8_t iv_raw[16];
  uint8_t *d_buf;
  uint8_t *e_buf;
  uint8_t *check_d_buf;
  uint8_t *check_e_buf;
  BIGNUM *sk;

  unique_ptr<Log::Stub> stub = Log::NewStub(CreateChannel(logAddr, InsecureChannelCredentials()));
  AuthRequest req;
  AuthCheckRequest checkReq;
  AuthResponse resp;
  AuthCheckResponse checkResp;
  ClientContext client_ctx;
  ClientContext client_ctx2;

  CHECK_A (out = BN_new());
  CHECK_A (sk = BN_new());
  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (mdctx2 = EVP_MD_CTX_create());
  CHECK_A (mdctx3 = EVP_MD_CTX_create());
  CHECK_A (ctx = BN_CTX_new());
  CHECK_A (sig = ECDSA_SIG_new());
  CHECK_A (key = EC_KEY_new());
  pkey = EVP_PKEY_new();
  R = EC_POINT_new(Params_group(params));

  //fprintf(stderr, "det2f: going to hash app id\n");
  //fprintf(stderr, "det2f: hashed app id\n");

  /* Compute signed message: hash of appId, user presence, counter, and
   * challenge. */
  memcpy(message_buf, app_id, SHA256_DIGEST_LENGTH);
  memcpy(message_buf + SHA256_DIGEST_LENGTH, &flags, sizeof(flags));
  memcpy(message_buf + SHA256_DIGEST_LENGTH + sizeof(flags), ctr, 4 * sizeof(uint8_t));
  memcpy(message_buf + SHA256_DIGEST_LENGTH + sizeof(flags) + 4 * sizeof(uint8_t), challenge, U2F_NONCE_SIZE);
  /*fprintf(stderr, "det2f: AUTH DATA: ");
  for (int i = 0; i < message_buf_len; i++) {
    fprintf(stderr, "%d ", message_buf[i]);
  }
  fprintf(stderr, "\n");*/

  EVP_DigestInit_ex(mdctx2, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx2, message_buf, message_buf_len);
  EVP_DigestFinal(mdctx2, hash_out, NULL);

  RAND_bytes(iv_raw, 16);
  memcpy((uint8_t *)&iv, iv_raw, 16);

//  memset(enc_key, 0, 16);
  memcpy((uint8_t *)&enc_key_128, enc_key, 16);
  aes_128_ctr(enc_key_128, iv, app_id, ct, SHA256_DIGEST_LENGTH, 0);
  STOP_TIMER("setup garbage"); 

  //fprintf(stderr, "det2f: proving circuit\n");
  //req.set_digest(hash_out, 32);
  START_TIMER;
  for (int i = 0; i < NUM_ROUNDS; i++) {
    workers[i] = thread(ProveCtCircuit, app_id, SHA256_DIGEST_LENGTH * 8, message_buf, message_buf_len * 8, hash_out, ct, enc_key, enc_key_comm, r_open, iv, numRands, &proof[i]);
    //ProveCtCircuit(app_id, SHA256_DIGEST_LENGTH * 8, message_buf, message_buf_len * 8, hash_out, ct, enc_key, enc_key_comm, r_open, iv, numRands, &proof);
  }

  for (int i = 0; i < NUM_ROUNDS; i++) {
    workers[i].join();
    proof_buf[i] = proof[i].Serialize(&proof_buf_len);
    req.add_proof(proof_buf[i], proof_buf_len);
  }
  STOP_TIMER("Prover time");
  //fprintf(stderr, "det2f: proof_buf_len = %d\n", proof_buf_len);
  //req.set_proof(proof_buf, proof_buf_len);
  //fprintf(stderr, "det2f: message_buf_len = %d\n", message_buf_len);
  req.set_challenge(message_buf, message_buf_len);
  req.set_ct(ct, SHA256_DIGEST_LENGTH);
  //req.set_digest(hash_out, 32);
  // TODO real IV
  //memset(iv_raw, 0, 16);
  req.set_iv(iv_raw, 16);
  START_TIMER;
  if (!noRegistration) {
    ThresholdSign(out, hash_out, sk_map[string((const char *)key_handle, MAX_KH_SIZE)], req);
  } else {
    ThresholdSign(out, hash_out, sk, req);
  }
  //INIT_TIMER;
  //START_TIMER;

  /* Output signature. */
  //fprintf(stderr, "encoding sig\n");
  memset(sig_out, 0, MAX_ECDSA_SIG_SIZE);
  //asn1_sigp(sig_out, r, s);
  asn1_sigp(sig_out, clientHints[auth_ctr].xcoord, out);
  len_byte = sig_out[1];
  sig_len = len_byte + 2;
  STOP_TIMER("ECDSA sign");

  /* Output message from device. */
  *flags_out = flags;
  *ctr_out = ctr32;
  //memcpy(ctr_out, ctr, sizeof(uint32_t));
  //fprintf(stderr, "det2f: counter out = %d\n", *ctr_out);

  auth_ctr++;
  fprintf(stderr, "about to return\n");
  STOP_TIMER("authenticate time");

cleanup:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  //fprintf(stderr, "det2f: sig_len = %d vs %d\n", sig_len, MAX_ECDSA_SIG_SIZE);
  return rv == OKAY ? sig_len : ERROR;
}

