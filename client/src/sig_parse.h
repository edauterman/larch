// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _SIG_PARSE_H
#define _SIG_PARSE_H

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C"{
#endif

/* Parse ASN1 encoded DSA signature. */
int dsa_sig_unpack(unsigned char* sig, int sig_len, BIGNUM* r_bn, BIGNUM* s_bn);

#ifdef __cplusplus
}
#endif
#endif

