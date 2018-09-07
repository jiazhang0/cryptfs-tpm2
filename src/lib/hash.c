/*
 * Copyright (c) 2016-2017, Wind River Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:
 *        Jia Zhang <zhang.jia@linux.alibaba.com>
 */

#include <cryptfs_tpm2.h>

#include "internal.h"

static int
tpm_hash(TPMI_ALG_HASH hash_alg, BYTE *data, UINT16 data_len,
	 BYTE *hash, UINT16 hash_size)
{
	TPM2B_MAX_BUFFER data_buf;

#ifndef TSS2_LEGACY_V1 
	if (data_len > sizeof(data_buf.buffer)) {
#else
	if (data_len > sizeof(data_buf.t.buffer)) {
#endif
		err("The data to be hashed is too large\n");
		return -1;
	}

#ifndef TSS2_LEGACY_V1 
	data_buf.size = data_len;
	memcpy(data_buf.buffer, data, data_len);
	TPM2B_DIGEST digest = { hash_size, };
#else
	data_buf.t.size = data_len;
	memcpy(data_buf.t.buffer, data, data_len);
	TPM2B_DIGEST digest = { { hash_size, } };
#endif

	UINT32 rc = Tss2_Sys_Hash(cryptfs_tpm2_sys_context, NULL, &data_buf,
				  hash_alg, TPM2_RH_NULL, &digest, NULL,
				  NULL);
	if (rc != TPM2_RC_SUCCESS) {
		err("Unable to calculate the digest (%#x)\n", rc);
		return -1;
	}

#ifndef TSS2_LEGACY_V1 
	memcpy(hash, digest.buffer, hash_size);
#else
	memcpy(hash, digest.t.buffer, hash_size);
#endif
	return 0;
}

int
sha1_digest(BYTE *data, UINT16 data_len, BYTE *hash)
{
	return tpm_hash(TPM2_ALG_SHA1, data, data_len, hash, TPM2_SHA1_DIGEST_SIZE);
}

int
hash_digest(TPMI_ALG_HASH hash_alg, BYTE *data, UINT16 data_len, BYTE *hash)
{
	UINT16 hash_size;

	if (util_digest_size(hash_alg, &hash_size))
		return -1;

	return tpm_hash(hash_alg, data, data_len, hash, hash_size);
}
