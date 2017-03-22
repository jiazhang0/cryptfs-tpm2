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
cryptfs_tpm2_unseal_passphrase(TPMI_ALG_HASH pcr_bank_alg, void **passphrase,
			       size_t *passphrase_size)
{
	struct session_complex s;
	char secret[256];
	unsigned int secret_size = sizeof(secret);

	get_passphrase_secret(secret, &secret_size);

	if (pcr_bank_alg != TPM_ALG_NULL) {
		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;

		if (policy_session_create(&s, TPM_SE_POLICY, policy_digest_alg))
			return -1;

		TPML_PCR_SELECTION pcrs;
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		pcrs.count = 1;
		pcrs.pcrSelections->hash = pcr_bank_alg;
		pcrs.pcrSelections->sizeofSelect = PCR_SELECT_MAX;
		memset(pcrs.pcrSelections->pcrSelect, 0, PCR_SELECT_MAX);
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

	TPM2B_SENSITIVE_DATA out_data = {{ sizeof(TPM2B_SENSITIVE_DATA)-2, }};

	UINT32 rc = Tss2_Sys_Unseal(cryptfs_tpm2_sys_context,
				    CRYPTFS_TPM2_PASSPHRASE_HANDLE, &s.sessionsData,
				    &out_data, &s.sessionsDataOut);
	policy_session_destroy(&s);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to unseal the passphrase object (%#x)\n", rc);
		return -1;
	}

	info("Succeed to unseal the passphrase (%d-byte)\n", out_data.t.size);

	*passphrase = malloc(out_data.t.size);
	if (!*passphrase)
		return -1;

	memcpy(*passphrase, out_data.t.buffer, out_data.t.size);
	*passphrase_size = out_data.t.size;

	return 0;
}
