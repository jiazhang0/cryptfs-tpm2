/*
 * Policy generation
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

static int
extend_pcr_policy_digest(TPMI_DH_OBJECT session_handle,
			 TPML_PCR_SELECTION *pcrs,
			 TPMI_ALG_HASH policy_digest_alg)
{
	unsigned int nr_pcr = 0;

	/* Calculate the total number of requested PCRs */
	for (UINT32 c = 0; c < pcrs->count; ++c) {
		TPMS_PCR_SELECTION *pcr_sel = pcrs->pcrSelections + c;

		for (UINT8 s = 0; s < pcr_sel->sizeofSelect; ++s) {
			BYTE *sel = pcr_sel->pcrSelect + s;

			for (unsigned int i = 0; i < sizeof(BYTE) * 8; ++i) {
				if (*sel & (1 << i))
					++nr_pcr;
			}
		}
	}

	if (!nr_pcr) {
		err("No PCR policy applied");
		return -1;
	}

	/* Obviously I'm lazy of using malloc() here */
	TPML_DIGEST pcr_digests[IMPLEMENTATION_PCR];
	TPML_PCR_SELECTION pcrs_out;
	UINT32 pcr_update_counter;

	UINT32 rc = Tss2_Sys_PCR_Read(cryptfs_tpm2_sys_context, NULL, pcrs,
				      &pcr_update_counter, &pcrs_out,
				      pcr_digests, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to read the PCRs (%#x)\n", rc);
		return -1;
	}

	UINT16 alg_size;
	if (util_digest_size(policy_digest_alg, &alg_size))
		return -1;

	nr_pcr = 0;
	TPM2B_DIGEST digest_tpm;

	for (UINT32 c = 0; c < pcrs->count && c < pcrs_out.count; ++c) {
		TPMS_PCR_SELECTION *pcr_sel = pcrs->pcrSelections + c;
		TPMS_PCR_SELECTION *pcr_sel_real = pcrs_out.pcrSelections + c;

		for (UINT8 s = 0; s < pcr_sel->sizeofSelect &&
				  s < pcr_sel_real->sizeofSelect; ++s) {
			BYTE *sel = pcr_sel->pcrSelect + s;
			BYTE *sel_real = pcr_sel_real->pcrSelect + s;

			if (!*sel)
				continue;

			for (unsigned int i = 0; i < sizeof(BYTE) * 8; ++i) {
				if (!(*sel & (1 << i)))
					continue;

				/* Check whether the input pcrs contain unsupported PCRs */
				if (!(*sel_real & (1 << i))) {
					err("PCR %x is not supported\n",
					    s * 8 + i);
					return -1;
				}

				if (nr_pcr) {
					/* Be lazy of using malloc() */
					TPM2B_DIGEST data[2];

					data->t.size = alg_size * 2;
					memcpy(data->t.buffer,
					       digest_tpm.t.buffer,
					       alg_size);
					memcpy(data->t.buffer + alg_size,
					       pcr_digests->digests[nr_pcr].t.buffer,
					       alg_size);

					if (hash_digest(policy_digest_alg,
							data->t.buffer,
							data->t.size,
							digest_tpm.t.buffer))
						return -1;
				} else {
					if (hash_digest(policy_digest_alg,
						        pcr_digests->digests[nr_pcr].t.buffer,
						        pcr_digests->digests[nr_pcr].t.size,
							digest_tpm.t.buffer))
						return -1;
				}

				++nr_pcr;
			}
		}
	}

	rc = Tss2_Sys_PolicyPCR(cryptfs_tpm2_sys_context, session_handle,
                                NULL, &digest_tpm, &pcrs_out, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to set the policy for PCRs (%#x)\n", rc);
		return -1;
	}

	return 0;
}

int
pcr_policy_extend(TPMI_DH_OBJECT session_handle, TPML_PCR_SELECTION *pcrs,
		  TPMI_ALG_HASH policy_digest_alg)
{
	return extend_pcr_policy_digest(session_handle, pcrs,
					policy_digest_alg);
}

int
password_policy_extend(TPMI_DH_OBJECT session_handle)
{
	UINT32 rc = Tss2_Sys_PolicyPassword(cryptfs_tpm2_sys_context,
					    session_handle, NULL, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to set the policy for password (%#x)\n", rc);
		return -1;
	}

	return 0;
}