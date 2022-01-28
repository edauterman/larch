#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "common.h"

/*
 * Use SHA-256 to hash the string in `bytes_in`
 * with the integer given in `counter`.
 */
static int
hash_once (EVP_MD_CTX *mdctx, uint8_t *bytes_out,
    const uint8_t *bytes_in, int inlen, uint16_t counter)
{
  int rv = ERROR;
  CHECK_C (EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL));
  CHECK_C (EVP_DigestUpdate (mdctx, &counter, sizeof counter));
  CHECK_C (EVP_DigestUpdate (mdctx, bytes_in, inlen));
  CHECK_C (EVP_DigestFinal_ex (mdctx, bytes_out, NULL));

cleanup:
  return rv;
}

/*
 * Output a string of pseudorandom bytes by hashing a
 * counter with the bytestring provided:
 *    Hash(0|bytes_in) | Hash(1|bytes_in) | ...
 */
int hash_to_bytes (uint8_t *bytes_out, int outlen,
    const uint8_t *bytes_in, int inlen)
{
  int rv = ERROR;
  uint16_t counter = 0;
  uint8_t buf[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx = NULL;
  int bytes_filled = 0;

  CHECK_A (mdctx = EVP_MD_CTX_create());

  do {
    const int to_copy = SHA256_DIGEST_LENGTH > outlen - bytes_filled ? outlen - bytes_filled : SHA256_DIGEST_LENGTH;
    CHECK_C (hash_once (mdctx, buf, bytes_in, inlen, counter));
    memcpy (bytes_out + bytes_filled, buf, to_copy);

    counter++;
    bytes_filled += SHA256_DIGEST_LENGTH;
  } while (bytes_filled < outlen);

cleanup:

  if (mdctx) EVP_MD_CTX_destroy (mdctx);
  return rv;
}
