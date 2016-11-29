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
cryptfs_tpm2_unseal_passphrase(TPMI_ALG_HASH pcr_bank_alg, void **passphrase,
			       size_t *passphrase_size)
{
	struct session_complex s;

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
				CRYPTFS_TPM2_PASSPHRASE_SECRET);
	} else
		password_session_create(&s, CRYPTFS_TPM2_PASSPHRASE_SECRET);

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