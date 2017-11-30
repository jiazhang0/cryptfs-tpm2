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
 *        Jia Zhang <qianyue.zj@alibaba-inc.com>
 */

#include <cryptfs_tpm2.h>

#include "internal.h"

int
cryptfs_tpm2_unseal_passphrase(TPMI_ALG_HASH pcr_bank_alg, void **passphrase,
			       size_t *passphrase_size)
{
	struct session_complex s;
	char secret[256];
	unsigned int secret_size;

	secret_size = sizeof(secret);
	get_passphrase_secret(secret, &secret_size);

redo:
	if (pcr_bank_alg != TPM2_ALG_NULL) {
		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;

		if (policy_session_create(&s, TPM2_SE_POLICY, policy_digest_alg))
			return -1;

		TPML_PCR_SELECTION pcrs;
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		pcrs.count = 1;
		pcrs.pcrSelections->hash = pcr_bank_alg;
		pcrs.pcrSelections->sizeofSelect = TPM2_PCR_SELECT_MAX;
		memset(pcrs.pcrSelections->pcrSelect, 0, TPM2_PCR_SELECT_MAX);
		pcrs.pcrSelections->pcrSelect[pcr_index / 8] |=
			(1 << (pcr_index % 8));

		if (pcr_policy_extend(s.session_handle, &pcrs,
				      policy_digest_alg)) {
			policy_session_destroy(&s);
			return -1;
		}

		if (password_policy_extend(s.session_handle)) {
			policy_session_destroy(&s);
			return -1;
		}

		/* TODO: move this call to policy_session_create() */
		policy_auth_set(&s.sessionData, s.session_handle,
				(char *)secret, secret_size);
	} else
		password_session_create(&s, (char *)secret, secret_size);

	TPM2B_SENSITIVE_DATA out_data = { sizeof(TPM2B_SENSITIVE_DATA)-2, };

	UINT32 rc;

	rc = Tss2_Sys_Unseal(cryptfs_tpm2_sys_context,
			     CRYPTFS_TPM2_PASSPHRASE_HANDLE,
			     &s.sessionsData, &out_data,
			     &s.sessionsDataOut);
	policy_session_destroy(&s);
	if (rc != TPM2_RC_SUCCESS) {
		if (rc == TPM2_RC_LOCKOUT) {
			if (da_reset() == EXIT_SUCCESS)
				goto redo;
		} else if (tpm2_rc_is_format_one(rc) &&
			   (((tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_BAD_AUTH) ||
			   ((tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_AUTH_FAIL))) {
			err("Wrong passphrase secret specified\n");

			secret_size = sizeof(secret);

			if (cryptfs_tpm2_util_get_passphrase_secret((uint8_t *)secret,
								    &secret_size) ==
								    EXIT_SUCCESS)
				goto redo;
		}

		err("Unable to unseal the passphrase object (%#x)\n", rc);
		return -1;
	}

	info("Succeed to unseal the passphrase (%d-byte)\n", out_data.size);

	*passphrase = malloc(out_data.size);
	if (!*passphrase)
		return -1;

	memcpy(*passphrase, out_data.buffer, out_data.size);
	*passphrase_size = out_data.size;

	return 0;
}
