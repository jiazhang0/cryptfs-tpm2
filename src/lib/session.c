/*
 * Libcryptfs-tpm2 constructor and destructor
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

static void
set_password_auth(TPMS_AUTH_COMMAND *sessionData, char *auth_password)
{
	sessionData->sessionHandle = TPM_RS_PW;
	sessionData->nonce.t.size = 0;
	*((UINT8 *)((void *)&sessionData->sessionAttributes)) = 0;

	if (!auth_password)
		sessionData->hmac.t.size = 0;
	else {
		sessionData->hmac.t.size = strlen(auth_password);
		memcpy((char *)sessionData->hmac.t.buffer, auth_password,
		       sessionData->hmac.t.size);
	}
}

void
session_init(struct session_complex *s, char *auth_password)
{
	set_password_auth(&s->sessionData, auth_password);
	s->sessionDataArray[0] = &s->sessionData;
	s->sessionsData.cmdAuthsCount = 1;
	s->sessionsData.cmdAuths = s->sessionDataArray;

	s->sessionDataOutArray[0] = &s->sessionDataOut;
	s->sessionsDataOut.rspAuthsCount = 1;
	s->sessionsDataOut.rspAuths = s->sessionDataOutArray;
}