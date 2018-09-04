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

int
cryptefs_tpm2_get_random(uint8_t *random, size_t *req_size)
{
	TPM2B_DIGEST random_bytes = { sizeof(TPM2B_DIGEST) - 2, };
	TPM2_RC rc;

	rc = Tss2_Sys_GetRandom(cryptfs_tpm2_sys_context, NULL, *req_size,
				&random_bytes, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		err("Unable to get the random number (%#x)\n", rc);
		return -1;
	}

	if (random_bytes.size < *req_size) {
		*req_size = random_bytes.size;
		warn("Random number truncated to %d-byte\n",
		     random_bytes.size);
	}

	cryptfs_tpm2_util_hex_dump("RNG random", random_bytes.buffer,
				   random_bytes.size);

	memcpy(random, random_bytes.buffer, *req_size);

	return 0;
}
