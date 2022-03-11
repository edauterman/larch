// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef __CROS_EC_INCLUDE_X509_H
#define __CROS_EC_INCLUDE_X509_H

#include <stddef.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "params.h"

/**
 * Top-level construction of the fob attestation certificate. Certificate is
 * ASN.1 DER encoded. key is both the public key in the certificate and the key
 * used to sign the certificate. cert must be a buffer of at least
 * MAX_CERT_SIZE.
 *
 */
int generate_cert(const_Params params, EC_KEY *key, uint8_t* cert);

#endif
