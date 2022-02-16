#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <stdbool.h>

/*
 * Return codes. For consistency with OpenSSL, we use
 * non-zero values to denote success.
 */
#define OKAY 1
#define ERROR 0

#define DEBUG 0
#define debug_print(args ...) if (DEBUG) fprintf(stderr, args)

/* Check a call that should return OKAY. */
#define CHECK_C(expr) do {\
  (rv = (expr));\
  if (rv != OKAY) {\
    goto cleanup;\
  }\
} while(false);

/* Check an allocation that should return non-NULL.*/
#define CHECK_A(expr) do {\
  (rv = ((expr) != NULL));\
  if (rv != OKAY) {\
    goto cleanup;\
  }\
} while(false);

/* Print BIGNUM to stdout. */
#define BN_DEBUG(t, a) do { printf("%s: ", t); BN_print_fp(stdout, a); printf("\n"); } while(0);

/* Print EC_POINT to stdout. */
#define EC_DEBUG(t, group, point, ctx) do { \
  char* c = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);\
  printf("%s: %s\n", t, c); \
  free(c); } while(0);

#ifdef __cplusplus
}
#endif

int hash_to_bytes(uint8_t *bytes_out, int outlen, const uint8_t *bytes_in, int inlen);

#endif
