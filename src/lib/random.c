/*
 * BSD 2-clause "Simplified" License
 *
 * Copyright (c) 2016-2017, Lans Zhang <jia.zhang@windriver.com>, Wind River Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:
 * 	Lans Zhang <jia.zhang@windriver.com>
 */

#include <cryptfs_tpm2.h>

#include "internal.h"

int
cryptefs_tpm2_get_random(void *random, UINT16 req_size)
{
	TPM2B_DIGEST random_bytes = { { sizeof(TPM2B_DIGEST)-2, } };
	TPM_RC rc;

	rc = Tss2_Sys_GetRandom(cryptfs_tpm2_sys_context, NULL, req_size,
				&random_bytes, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		err("Unable to get the random number (%#x)\n", rc);
		return -1;
	}

	dbg("random number size: %d-byte\n", random_bytes.t.size);
	for (UINT16 i = 0; i < random_bytes.t.size; i++)
		dbg_cont("%#2.2x ", random_bytes.t.buffer[i]);
	dbg_cont("\n");

	if (random_bytes.t.size < req_size)
		warn("Random number truncated to %d-byte\n", random_bytes.t.size);

	memcpy(random, random_bytes.t.buffer, random_bytes.t.size);

	return 0;
}