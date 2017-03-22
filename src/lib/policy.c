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

static int
extend_pcr_policy_digest(TPMI_DH_OBJECT session_handle,
			 TPML_PCR_SELECTION *pcrs,
			 TPMI_ALG_HASH policy_digest_alg)
{
	UINT16 alg_size;

	if (util_digest_size(policy_digest_alg, &alg_size))
		return -1;

	unsigned int nr_pcr = 0;

	/* Calculate the total number of requested PCRs */
	for (UINT32 c = 0; c < pcrs->count; ++c) {
		TPMS_PCR_SELECTION *pcr_sel = pcrs->pcrSelections + c;

		for (UINT8 s = 0; s < pcr_sel->sizeofSelect; ++s) {
			BYTE *sel = pcr_sel->pcrSelect + s;

			if (!*sel)
				continue;

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
	TPML_DIGEST pcr_digests[(nr_pcr + 7) / 8];
	TPML_PCR_SELECTION pcrs_out;
	UINT32 pcr_update_counter;

	pcr_digests->count = nr_pcr;

	UINT32 rc = Tss2_Sys_PCR_Read(cryptfs_tpm2_sys_context, NULL, pcrs,
				      &pcr_update_counter, &pcrs_out,
				      pcr_digests, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to read the PCRs (%#x)\n", rc);
		return -1;
	}

	unsigned nr_pcr_real = 0;
	TPM2B_DIGEST digest_tpm = { { alg_size, } };

	for (UINT32 c = 0; c < pcrs_out.count; ++c) {
		TPMS_PCR_SELECTION *pcr_sel = pcrs->pcrSelections + c;
		TPMS_PCR_SELECTION *pcr_sel_real = pcrs_out.pcrSelections + c;

		for (UINT8 s = 0; s < pcr_sel_real->sizeofSelect; ++s) {
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

				if (nr_pcr_real) {
					BYTE data[sizeof(TPMU_HA) * 2];

					memcpy(data, digest_tpm.t.buffer,
					       alg_size);
					memcpy(data + alg_size,
					       pcr_digests->digests[nr_pcr_real].t.buffer,
					       alg_size);

					if (hash_digest(policy_digest_alg,
							data, alg_size * 2,
							digest_tpm.t.buffer))
						return -1;
				} else {
					if (hash_digest(policy_digest_alg,
						        pcr_digests->digests[nr_pcr_real].t.buffer,
						        pcr_digests->digests[nr_pcr_real].t.size,
							digest_tpm.t.buffer))
						return -1;
				}

				++nr_pcr_real;
			}
		}
	}

	if (nr_pcr_real != nr_pcr) {
		err("The supported PCRs (%d) are less than the "
		    "specified (%d)\n", nr_pcr_real, nr_pcr);
		return -1;
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