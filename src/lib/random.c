/*
 * Random number generation
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