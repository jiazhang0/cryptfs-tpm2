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

int
cryptfs_tpm2_read_pcr(TPMI_ALG_HASH bank_alg, unsigned int index,
		      BYTE *out)
{
	TPML_PCR_SELECTION pcrs;

	pcrs.count = 1;
	pcrs.pcrSelections->hash = bank_alg;
	pcrs.pcrSelections->sizeofSelect = 3;
	memset(pcrs.pcrSelections->pcrSelect, 0, TPM2_PCR_SELECT_MAX);
	pcrs.pcrSelections->pcrSelect[index / 8] |= (1 << (index % 8));

	/* Obviously I'm lazy of using malloc() here */
	TPML_DIGEST pcr_digest;

	TPML_PCR_SELECTION pcrs_out;
	UINT32 pcr_update_counter;
	UINT32 rc;

	rc = Tss2_Sys_PCR_Read(cryptfs_tpm2_sys_context, NULL, &pcrs,
			       &pcr_update_counter, &pcrs_out, &pcr_digest,
			       NULL);
	if (rc != TPM2_RC_SUCCESS) {
		err("Unable to read the PCR (%#x)\n", rc);
		return -1;
	}

	if (pcrs_out.count != 1)
		return -1;

	if (pcrs_out.pcrSelections->hash != bank_alg)
		return -1;

	if (pcrs_out.pcrSelections->sizeofSelect < align_up(index, 8) / 8)
		return -1;

	if (!(pcrs_out.pcrSelections->pcrSelect[index / 8] & (1 << (index % 8))))
		return -1;

	if (pcr_digest.count != 1)
		return -1;

	UINT16 alg_size;

	util_digest_size(bank_alg, &alg_size);

#ifndef TSS2_LEGACY_V1
	if (pcr_digest.digests->size != alg_size)
		return -1;

	memcpy(out, pcr_digest.digests->buffer, alg_size);
#else
	if (pcr_digest.digests->t.size != alg_size)
		return -1;

	memcpy(out, pcr_digest.digests->t.buffer, alg_size);
#endif
	return 0;
}
