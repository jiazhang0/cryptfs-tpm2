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
capability_read_public(TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public_out)
{
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA capability_data;
	UINT32 rc = Tss2_Sys_GetCapability(cryptfs_tpm2_sys_context, NULL,
					   TPM_CAP_HANDLES, TPM_HT_PERSISTENT,
          				   TPM_PT_HR_PERSISTENT, &more_data,
					   &capability_data, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to get the TPM persistent handles (%#x)", rc);
		return -1;
	};

	dbg("%d persistent objects detected:\n", capability_data.data.handles.count);
	for (UINT32 i = 0; i < capability_data.data.handles.count; ++i) {
		TPMI_DH_OBJECT h = capability_data.data.handles.handle[i];

        	dbg_cont("  [%02d] %#8.8x\n", i, h);

		if (h != handle)
			continue;

        	/* Actually TPM2_ReadPublic doesn't require any authorization */
        	struct session_complex s;
		password_session_create(&s, NULL, 0);

		TPM2B_NAME name = { { sizeof(TPM2B_NAME)-2, } };
		TPM2B_NAME qualified_name = { { sizeof(TPM2B_NAME)-2, } };

		rc = Tss2_Sys_ReadPublic(cryptfs_tpm2_sys_context, handle,
					 NULL, public_out, &name,
					 &qualified_name, &s.sessionsDataOut);
		if (rc != TPM_RC_SUCCESS) {
			err("Unable to read the public area for the "
			    "persistent handle %#8.8x (%#x)", handle, rc);
			return -1;
		}

		return 0;
	}

	return -1;
}
