/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include "prov/securitycheck.h"
#include "prov/providercommonerr.h"

int securitycheck_enabled(void)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    /* TODO(3.0): make this configurable */
    return 1;
#else
    return 0;
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
}

int digest_rsa_sign_get_md_nid(const EVP_MD *md, int sha1_allowed)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (securitycheck_enabled())
        return digest_get_approved_nid_with_sha1(md, sha1_allowed);
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return digest_get_approved_nid(md);
}