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

TSS2_SYS_CONTEXT *cryptfs_tpm2_sys_context;

static TSS2_TCTI_CONTEXT *tcti_context;

static TSS2_RC
init_sys_context(void)
{
	TSS2_ABI_VERSION tss2_abi_version = {
		TSSWG_INTEROP,
		TSS_SAPI_FIRST_FAMILY,
		TSS_SAPI_FIRST_LEVEL,
		TSS_SAPI_FIRST_VERSION
	};
	TSS2_SYS_CONTEXT *sys_context;
	UINT32 size;
	TSS2_RC rc;

	/* Get the size needed for system context structure */
	size = Tss2_Sys_GetContextSize(0);

	/* Allocate the space for the system context structure */
	sys_context = malloc(size);
	if (!sys_context) {
		err("Unable to allocate system context\n");
		return TSS2_TCTI_RC_BAD_CONTEXT;
	}

        rc = Tss2_Sys_Initialize(sys_context, size, tcti_context,
				 &tss2_abi_version);
        if (rc != TSS2_RC_SUCCESS) {
		err("Unable to initialize system context\n");
		free(sys_context);
		return rc;
	}

	cryptfs_tpm2_sys_context = sys_context;

	return TSS2_RC_SUCCESS;
}

static void
teardown_sys_context(void)
{
	Tss2_Sys_Finalize(cryptfs_tpm2_sys_context);
	free(cryptfs_tpm2_sys_context);
	cryptfs_tpm2_sys_context = NULL;
}

void __attribute__ ((constructor))
libcryptfs_tpm2_init(void)
{
	tcti_context = cryptfs_tpm2_tcti_init_context();
	if (!tcti_context)
		exit(1);

	init_sys_context();
}

void __attribute__((destructor))
libcryptfs_tpm2_fini(void)
{
	teardown_sys_context();
	cryptfs_tpm2_tcti_teardown_context(tcti_context);
	tcti_context = NULL;
}
