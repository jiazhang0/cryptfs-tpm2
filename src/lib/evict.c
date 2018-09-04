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
evictcontrol(TPMI_DH_OBJECT obj_handle, TPMI_DH_PERSISTENT persist_handle)
{
	uint8_t owner_auth[sizeof(TPMU_HA)];
	unsigned int owner_auth_size = sizeof(owner_auth);

	if (cryptfs_tpm2_option_get_owner_auth(owner_auth, &owner_auth_size))
		return EXIT_FAILURE;
	
	struct session_complex s;
	UINT32 rc;

re_auth_owner:
	password_session_create(&s, (char *)owner_auth, owner_auth_size);
redo:
	rc = Tss2_Sys_EvictControl(cryptfs_tpm2_sys_context, TPM2_RH_OWNER,
				   obj_handle, &s.sessionsData, persist_handle,
				   &s.sessionsDataOut);
	if (rc != TPM2_RC_SUCCESS) {
		if (rc == TPM2_RC_LOCKOUT) {
			if (da_reset() == EXIT_SUCCESS)
				goto redo;
		} else if (tpm2_rc_is_format_one(rc) &&
			   (tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_BAD_AUTH) {
			owner_auth_size = sizeof(owner_auth);

			if (cryptfs_tpm2_util_get_owner_auth(owner_auth,
							     &owner_auth_size) ==
							     EXIT_SUCCESS)
				goto re_auth_owner;
		}

        	err("Unable to evictcontrol the object (%#x)\n", rc);
		return -1;
	}

	return 0;
}

int
cryptfs_tpm2_evict_primary_key(void)
{
	return evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
			    (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE);
}

int
cryptfs_tpm2_evict_passphrase(void)
{
	return evictcontrol((TPMI_DH_OBJECT)CRYPTFS_TPM2_PASSPHRASE_HANDLE,
			    (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE);
}

int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle)
{
	return evictcontrol(handle,
			    (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PRIMARY_KEY_HANDLE);
}

int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle)
{
	return evictcontrol(handle,
			    (TPMI_DH_PERSISTENT)CRYPTFS_TPM2_PASSPHRASE_HANDLE);
}
