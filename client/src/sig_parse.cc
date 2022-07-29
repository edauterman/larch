// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include "u2f.h"

/**
 * Trims off the leading zero bytes and copy it to a buffer aligning it to the end.
 */
static inline int trim_to_p256_bytes(unsigned char dst[P256_SCALAR_SIZE], unsigned char *src,
        int src_len) {
    int dst_offset;
    while (*src == '\0' && src_len > 0) {
        src++;
        src_len--;
    }
    if (src_len > P256_SCALAR_SIZE || src_len < 1) {
        return 0;
    }
    dst_offset = P256_SCALAR_SIZE - src_len;
    memset(dst, 0, dst_offset);
    memcpy(dst + dst_offset, src, src_len);
    return 1;
}

/**
 * Unpacks the ASN.1 DSA signature sequence.
 * Adapted from libmincrypt to support BIGNUMs.
 */
int dsa_sig_unpack(unsigned char* sig, int sig_len, BIGNUM* r_bn, BIGNUM* s_bn) {
    /*
     * Structure is:
     *   0x30 0xNN  SEQUENCE + s_length
     *     0x02 0xNN  INTEGER + r_length
     *       0xAA 0xBB ..   r_length bytes of "r" (offset 4)
     *     0x02 0xNN  INTEGER + s_length
     *       0xMM 0xNN ..   s_length bytes of "s" (offset 6 + r_len)
     */
    int seq_len;
    unsigned char r_bytes[P256_SCALAR_SIZE];
    unsigned char s_bytes[P256_SCALAR_SIZE];
    int r_len;
    int s_len;

    memset(r_bytes, 0, sizeof(r_bytes));
    memset(s_bytes, 0, sizeof(s_bytes));

    /*
     * Must have at least:
     * 2 bytes sequence header and length
     * 2 bytes R integer header and length
     * 1 byte of R
     * 2 bytes S integer header and length
     * 1 byte of S
     *
     * 8 bytes total
     */
    if (sig_len < 8 || sig[0] != 0x30 || sig[2] != 0x02) {
        return 0;
    }

    seq_len = sig[1];
    if ((seq_len <= 0) || (seq_len + 2 != sig_len)) {
        return 0;
    }

    r_len = sig[3];
    /*
     * Must have at least:
     * 2 bytes for R header and length
     * 2 bytes S integer header and length
     * 1 byte of S
     */
    if ((r_len < 1) || (r_len > seq_len - 5) || (sig[4 + r_len] != 0x02)) {
        return 0;
    }
    s_len = sig[5 + r_len];
   /**
     * Must have:
     * 2 bytes for R header and length
     * r_len bytes for R
     * 2 bytes S integer header and length
     */
    if ((s_len < 1) || (s_len != seq_len - 4 - r_len)) {
        return 0;
    }

    /*
     * ASN.1 encoded integers are zero-padded for positive integers. Make sure we have
     * a correctly-sized buffer and that the resulting integer isn't too large.
     */
    if (!trim_to_p256_bytes(r_bytes, &sig[4], r_len)
            || !trim_to_p256_bytes(s_bytes, &sig[6 + r_len], s_len)) {
        return 0;
    }

    BN_bin2bn(r_bytes, P256_SCALAR_SIZE, r_bn);
    BN_bin2bn(s_bytes, P256_SCALAR_SIZE, s_bn);

    return 1;
}
