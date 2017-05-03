/*
 * BSD 2-clause "Simplified" License
 *
 * Copyright (c) 2017, Lans Zhang <jia.zhang@windriver.com>, Wind River Systems, Inc.
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

static int
clear_lockout(const char *lockout_auth)
{
	unsigned int lockout_auth_size;

	if (!lockout_auth)
		lockout_auth_size = 0;
	else
		lockout_auth_size = strlen(lockout_auth);

	struct session_complex s;

	password_session_create(&s, (char *)lockout_auth, lockout_auth_size);

	UINT32 rc;

	rc = Tss2_Sys_DictionaryAttackLockReset(cryptfs_tpm2_sys_context,
						TPM_RH_LOCKOUT,
						&s.sessionsData,
						&s.sessionsDataOut);
        if (rc != TPM_RC_SUCCESS) {
		err("Unable to reset DA lockout (err: 0x%x)\n", rc);
		return EXIT_FAILURE;
	}

	info("Reset DA lockout\n");

        return EXIT_SUCCESS;
}

int
da_reset(void)
{
	bool required;
	int rc;

	rc = cryptfs_tpm2_capability_lockout_auth_required(&required);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	uint8_t lockout_auth[sizeof(TPMU_HA)];
	unsigned int lockout_auth_size = sizeof(lockout_auth);

	rc = cryptfs_tpm2_option_get_lockout_auth(lockout_auth,
						  &lockout_auth_size);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	if (required == false) {
		if (lockout_auth_size)
			warn("Ignore --lockout-auth due to lockout "
			     "authentication not required\n");

		return clear_lockout(NULL);
	}

	if (!lockout_auth_size) {
		warn("Please specify --lockout-auth to reset DA lockout\n");
		return EXIT_FAILURE;
	}

	int retry = 0;

	while (retry++ < CRYPTFS_TPM2_MAX_LOCKOUT_RETRY) {
		rc = clear_lockout((const char *)lockout_auth);
		if (rc == EXIT_SUCCESS)
			break;

		err("Wrong lockout authentication specified\n");

		if (get_input("Lockout Authentication: ", lockout_auth,
			      &lockout_auth_size) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

	return rc;
}

int
da_check_and_reset(void)
{
	bool in_lockout;
	int rc;

	rc = cryptfs_tpm2_capability_in_lockout(&in_lockout);
	if (rc == EXIT_SUCCESS && in_lockout == true)
		rc = da_reset();

	return rc;
}
