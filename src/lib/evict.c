/*
 * Object eviction
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
cryptfs_tpm2_evictcontrol(TPMI_DH_OBJECT obj_handle, TPMI_DH_PERSISTENT persist_handle,
			  char *auth_password)
{
	struct session_complex s;
	UINT32 rc;

	password_session_create(&s, auth_password);

	rc = Tss2_Sys_EvictControl(cryptfs_tpm2_sys_context, TPM_RH_OWNER,
				   obj_handle, &s.sessionsData, persist_handle,
				   &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to evictcontrol the object (%#x)\n", rc);
		return -1;
	}

	return 0;
}

int
cryptfs_tpm2_evict_primary_key(char *auth_password)
{
	return cryptfs_tpm2_evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 auth_password);
}

int
cryptfs_tpm2_evict_passphrase(char *auth_password)
{
	return cryptfs_tpm2_evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 auth_password);
}

int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle, char *auth_password)
{
	return cryptfs_tpm2_evictcontrol(handle,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 auth_password);
}

int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle, char *auth_password)
{
	return cryptfs_tpm2_evictcontrol(handle,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 auth_password);
}
