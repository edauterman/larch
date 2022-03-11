// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include "asn1.h"
#include "x509.h"
#include "common.h"

static void add_CN(ASN1* ctx) {
  SEQ_START(*ctx, t_SEQ, SEQ_SMALL) {
    SEQ_START(*ctx, t_SET, SEQ_SMALL) {
      SEQ_START(*ctx, t_SEQ, SEQ_SMALL) {
        asn1_object(ctx, OID(commonName));
        asn1_string(ctx, t_ASCII, "U2F");
      }
      SEQ_END(*ctx);
    }
    SEQ_END(*ctx);
  }
  SEQ_END(*ctx);
}

int generate_cert(const_Params params, EC_KEY *key,
                  uint8_t* cert) {
  int rv = ERROR;
  ASN1 ctx = {cert, 0};
  uint8_t digest[SHA256_DIGEST_LENGTH];
  const BIGNUM *r;
  const BIGNUM *s;
  EVP_MD_CTX *mdctx;
  ECDSA_SIG *sig;
  const EC_POINT *pk;

  CHECK_A (r = BN_new());
  CHECK_A (s = BN_new());
  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (pk = EC_KEY_get0_public_key(key));

  SEQ_START(ctx, t_SEQ, SEQ_LARGE) {  // outer seq
    // Grab current pointer to data to hash later.
    // Note this will fail if cert body + cert sign is less
    // than 256 bytes (SEQ_MEDIUM) -- not likely.
    uint8_t* body = ctx.p + ctx.n;

    // Cert body seq
    SEQ_START(ctx, t_SEQ, SEQ_MEDIUM) {
      // X509 v3
      SEQ_START(ctx, 0xa0, SEQ_SMALL) { asn1_int(&ctx, 2); }
      SEQ_END(ctx);

      // Serial number
      asn1_int(&ctx, 1);

      // Signature algo
      SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
        asn1_object(&ctx, OID(ecdsa_with_SHA256));
      }
      SEQ_END(ctx);

      // Issuer
      add_CN(&ctx);

      // Expiry
      SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
        asn1_string(&ctx, t_TIME, "20000101000000Z");
        asn1_string(&ctx, t_TIME, "20991231235959Z");
      }
      SEQ_END(ctx);

      // Subject
      add_CN(&ctx);

      // Subject pk
      SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
        // pk parameters
        SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
          asn1_object(&ctx, OID(id_ecPublicKey));
          asn1_object(&ctx, OID(prime256v1));
        }
        SEQ_END(ctx);
        // pk bits
        SEQ_START(ctx, t_BITS, SEQ_SMALL) {
          asn1_tag(&ctx, t_NULL);  // ?
          asn1_pub(&ctx, params, pk);
        }
        SEQ_END(ctx);
      }
      SEQ_END(ctx);

      // U2F usb transport indicator extension
      SEQ_START(ctx, 0xa3, SEQ_SMALL) {
        SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
          SEQ_START(ctx, t_SEQ, SEQ_SMALL) {
            asn1_object(&ctx, OID(fido_u2f));
            SEQ_START(ctx, t_BYTES, SEQ_SMALL) {
              SEQ_START(ctx, t_BITS, SEQ_SMALL) {
                asn1_tag(&ctx, 5);     // 5 zero bits
                asn1_tag(&ctx, 0x20);  // usb transport
              }
              SEQ_END(ctx);
            }
            SEQ_END(ctx);
          }
          SEQ_END(ctx);
        }
        SEQ_END(ctx);
      }
      SEQ_END(ctx);
    }
    SEQ_END(ctx);  // Cert body

    // Sign all of cert body
    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, body, ctx.p + ctx.n - body));
    CHECK_C (EVP_DigestFinal_ex(mdctx, digest, NULL));
    CHECK_A (sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, key));
    ECDSA_SIG_get0(sig, &r, &s);

    // Append X509 signature
    SEQ_START(ctx, t_SEQ, SEQ_SMALL);
    asn1_object(&ctx, OID(ecdsa_with_SHA256));
    SEQ_END(ctx);
    SEQ_START(ctx, t_BITS, SEQ_SMALL) {
      asn1_tag(&ctx, t_NULL);
      asn1_sig(&ctx, r, s);
    }
    SEQ_END(ctx);
  }
  SEQ_END(ctx);

cleanup:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  if (sig) ECDSA_SIG_free(sig);

  return ctx.n;
}
