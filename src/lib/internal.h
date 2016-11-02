/*
 * Internal header
 *
 * Copyright (c) 2016, Wind River Systems, Inc.
 * All rights reserved.
 *
 * See "LICENSE" for license terms.
 *
 * Author:
 *	  Lans Zhang <jia.zhang@windriver.com>
 */

#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <cryptfs_tpm2.h>

/* The persiste handle value for the primary key */
#define CRYPTFS_TPM2_PRIMARY_KEY_HANDLE		0x817FFFFF

/* The persiste handle value for the passphrase */
#define CRYPTFS_TPM2_PASSPHRASE_HANDLE		0x817FFFFE

/* The authorization password for the primary key */
#define CRYPTFS_TPM2_PRIMARY_KEY_SECRET		"H31i05"

/* The authorization password for the passphrase */
#define CRYPTFS_TPM2_PASSPHRASE_SECRET		"h31i05"

/* The PCR index used to seal/unseal the passphrase */
#define CRYPTFS_TPM2_PCR_INDEX			9

struct session_complex {
	TPMS_AUTH_COMMAND sessionData;
	TPMS_AUTH_COMMAND *sessionDataArray[1];
	TSS2_SYS_CMD_AUTHS sessionsData;

	TPMS_AUTH_RESPONSE sessionDataOut;
	TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
	TSS2_SYS_RSP_AUTHS sessionsDataOut;
};

extern TSS2_SYS_CONTEXT *cryptfs_tpm2_sys_context;

void
session_init(struct session_complex *s, char *auth_password);

#endif	/* __INTERNAL_H__ */