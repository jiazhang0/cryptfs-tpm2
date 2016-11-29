/*
 * Hash function
 *
 * Copyright (c) 2016, Wind River Systems, Inc.
 * All rights reserved.
 *
 * See "LICENSE" for license terms.
 *
 * Author:
 *	  Lans Zhang <jia.zhang@windriver.com>
 */

#include <cryptfs_tpm2.h>

#include "internal.h"

static int
tpm_hash(TPMI_ALG_HASH hash_alg, BYTE *data, UINT16 data_len,
	 BYTE *hash, UINT16 hash_size)
{
	TPM2B_MAX_BUFFER data_buf;

	data_buf.t.size = data_len;
	memcpy(data_buf.t.buffer, data, data_len);

	TPM2B_DIGEST digest = { { hash_size, } };

	UINT32 rc = Tss2_Sys_Hash(cryptfs_tpm2_sys_context, NULL, &data_buf,
				  hash_alg, TPM_RH_NULL, &digest, NULL,
				  NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to calculate the digest (%#x)\n", rc);
		return -1;
	}

	memcpy(hash, digest.t.buffer, digest.t.size);

	return 0;
}

int
sha1_digest(BYTE *data, UINT16 data_len, BYTE *hash)
{
	return tpm_hash(TPM_ALG_SHA1, data, data_len, hash, SHA1_DIGEST_SIZE);
}

int
hash_digest(TPMI_ALG_HASH hash_alg, BYTE *data, UINT16 data_len, BYTE *hash)
{
	UINT16 hash_size;

	if (util_digest_size(hash_alg, &hash_size))
		return -1;

	return tpm_hash(hash_alg, data, data_len, hash, hash_size);
}