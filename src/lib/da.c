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
						TPM2_RH_LOCKOUT,
						&s.sessionsData,
						&s.sessionsDataOut);
        if (rc != TPM2_RC_SUCCESS) {
		if (rc == TPM2_RC_LOCKOUT) {
			/*
			 * XXX: recover this sort of lockout via lockoutAuth
			 * policy.
			 */
			UINT32 recovery;
			int ret;

			ret = cryptfs_tpm2_capability_get_lockout_recovery(&recovery);
			if (ret == EXIT_SUCCESS)
				err("TPM lockout will be recovered within %d "
				    "seconds\n", recovery);
		}

		err("Unable to reset DA lockout (err: 0x%x)\n", rc);
		return EXIT_FAILURE;
	}

	info("Reset DA lockout\n");

        return EXIT_SUCCESS;
}

int
da_reset(void)
{
	UINT32 counter;
	int rc;

	rc = cryptfs_tpm2_capability_get_lockout_counter(&counter);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	UINT32 max_tries;

	rc = cryptfs_tpm2_capability_get_max_tries(&max_tries);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	dbg("counter (%d) VS max-tries (%d)\n", counter, max_tries);

	if (counter != max_tries) {
		info("Lockout already recovered\n");
		return EXIT_SUCCESS;
	}

	bool disabled;

	rc = cryptfs_tpm2_capability_da_disabled(&disabled);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	if (disabled == true) {
		info("DA protection is disabled\n");
		return EXIT_SUCCESS;
	}

	bool enforced;

	rc = cryptfs_tpm2_capability_lockout_enforced(&enforced);
	if (rc == EXIT_FAILURE)
		return EXIT_FAILURE;

	/*
	 * XXX: attempt to fix the DA policy with lockoutAuth.
	 */
	if (enforced == true) {
		err("Unable to reset DA because lockout is enforced\n");
		return EXIT_FAILURE;
	}

	bool required;

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

	if (lockout_auth_size) {
		rc = clear_lockout((const char *)lockout_auth);
		if (rc == EXIT_SUCCESS) {
			info("Automatically reset DA lockout\n");
			return rc;
		}

		err("Wrong lockout authentication specified by "
		    "--lockout-auth\n");
	}

	info("TPM is in lockout state. Need to type lockout authentication "
	     "to reset DA lockout\n");

	if (cryptfs_tpm2_option_get_interactive(&required))
		return EXIT_FAILURE;

	rc = EXIT_FAILURE;

	if (required == false)
		goto out;

	int retry = 0;

	while (retry++ < CRYPTFS_TPM2_MAX_LOCKOUT_RETRY) {
		if (get_input("Lockout Authentication: ", lockout_auth,
			      &lockout_auth_size) == EXIT_FAILURE)
			break;

		rc = clear_lockout((const char *)lockout_auth);
		if (rc == EXIT_SUCCESS)
			break;

		err("Wrong lockout authentication specified\n");
	}

out:
	if (rc == EXIT_SUCCESS)
		info("Automatically reset DA lockout\n");
	else
		warn("Please specify correct --lockout-auth to reset DA "
		     "lockout\n");

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
