/*
 * Library constructor and destructor
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

TSS2_SYS_CONTEXT *cryptfs_tpm2_sys_context;

static TSS2_TCTI_CONTEXT *tcti_context;

static TSS2_RC
init_tcti_context(void)
{
	TCTI_SOCKET_CONF cfg = {
		DEFAULT_HOSTNAME,
		DEFAULT_RESMGR_TPM_PORT
	};
	size_t size;
	TSS2_RC rc;

	rc = InitSocketTcti(NULL, &size, &cfg, 0);
	if (rc != TSS2_RC_SUCCESS) {
		err("Unable to get the size of tcti context\n");
		return rc;
	}

	tcti_context = (TSS2_TCTI_CONTEXT *)malloc(size);
	if(!tcti_context)
		rc = TSS2_TCTI_RC_BAD_CONTEXT;
	else {
        	rc = InitSocketTcti(tcti_context, &size, &cfg, 0);
		if (rc != TSS2_RC_SUCCESS) {
			err("Unable to initialize tcti context\n");
			free(tcti_context);
			tcti_context = NULL;
		}
	}

	return rc;
}

static void
teardown_tcti_context(void)
{
	tss2_tcti_finalize(tcti_context);
	free(tcti_context);
	tcti_context = NULL;
}

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
	TSS2_RC rc;

	rc = init_tcti_context();
	if (rc != TSS2_RC_SUCCESS)
		return;

	init_sys_context();
}

void __attribute__((destructor))
libcryptfs_tpm2_fini(void)
{
	teardown_sys_context();
	teardown_tcti_context();
}