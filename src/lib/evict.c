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
cryptfs_tpm2_evictcontrol(TPMI_DH_OBJECT obj_handle, TPMI_DH_PERSISTENT persist_handle,
			  char *auth_password, unsigned int auth_password_size)
{
	struct session_complex s;
	UINT32 rc;

	password_session_create(&s, auth_password, auth_password_size);

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
cryptfs_tpm2_evict_primary_key(char *auth_password,
			       unsigned int auth_password_size)
{
	return cryptfs_tpm2_evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 auth_password, auth_password_size);
}

int
cryptfs_tpm2_evict_passphrase(char *auth_password,
			      unsigned int auth_password_size)
{
	return cryptfs_tpm2_evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 auth_password, auth_password_size);
}

int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle, char *auth_password,
				 unsigned int auth_password_size)
{
	return cryptfs_tpm2_evictcontrol(handle,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
					 auth_password, auth_password_size);
}

int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle, char *auth_password,
				unsigned int auth_password_size)
{
	return cryptfs_tpm2_evictcontrol(handle,
					 (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
					 auth_password, auth_password_size);
}
