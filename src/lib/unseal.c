/*
 * Object unseal
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
cryptfs_tpm2_unseal_passphrase(void **passphrase, size_t *passphrase_size)
{
	UINT32 rc;

	struct session_complex s;
	session_init(&s, CRYPTFS_TPM2_PASSPHRASE_SECRET);

	TPM2B_SENSITIVE_DATA out_data = {{sizeof(TPM2B_SENSITIVE_DATA)-2, }};

	rc = Tss2_Sys_Unseal(cryptfs_tpm2_sys_context, CRYPTFS_TPM2_PASSPHRASE_HANDLE,
			     &s.sessionsData, &out_data, &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to unseal the passphrase object (%#x)\n", rc);
		return -1;
	}

	info("Succeed to unseal the passphrase (%d-byte)\n",out_data.t.size );

	*passphrase = malloc(out_data.t.size);
	if (!*passphrase)
		return -1;

	memcpy(*passphrase, out_data.t.buffer, out_data.t.size);
	*passphrase_size = out_data.t.size;

	return 0;
}