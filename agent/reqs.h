// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _AGENT_H
#define _AGENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>

#include "params.h"

using namespace std;

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
class KeyHandle {
  public:
  uint8_t data[MAX_KH_SIZE];
  KeyHandle(const uint8_t *data);
  bool operator<(const KeyHandle &src) const;
};


/* Run registration with origin specified by app_id. Outputs the key handle and
 * public key, and generates a self-signed cert and corresponding batch
 * signature (created entirely at the agent). Returns sum of length of
 * attestation certificate and batch signature, or 0 on failure.*/
int Register(const uint8_t *app_id, const uint8_t *challenge,
             uint8_t *key_handle_out, P256_POINT *pk_out, uint8_t *cert_sig_out);

/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Outputs the flags, counter, and
 * sanitized signature from the device. Returns the length of the signature, or
 * 0 on failure. */
int Authenticate(const uint8_t *app_id, const uint8_t *challenge,
                 const uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool checkOnly = false);

#endif

