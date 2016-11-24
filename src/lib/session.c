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

/*
 * Create an unsalted and unbound policy session for generating
 * the policy digest calculated by TPM.
 */
int
policy_session_create(struct session_complex *s, TPM_SE type,
		      TPMI_ALG_HASH hash_alg)
{
	UINT16 hash_alg_size;

	if (util_digest_size(hash_alg, &hash_alg_size))
		return -1;

	if (type != TPM_SE_POLICY && type != TPM_SE_TRIAL) {
		err("Invalid session type %#x specified\n", type);
		return -1;
	}

	TPM2B_ENCRYPTED_SECRET salt;
	salt.t.size = 0;

	/* No symmetric algorithm */
	TPMT_SYM_DEF symmetric;
	symmetric.algorithm = TPM_ALG_NULL;

	TPM2B_NONCE nonce_caller;
	nonce_caller.t.size = hash_alg_size;
	memset(nonce_caller.t.buffer, 0, nonce_caller.t.size);

	TPM2B_NONCE nonce_tpm;
	nonce_tpm.t.size = nonce_caller.t.size;

	UINT32 rc = Tss2_Sys_StartAuthSession(cryptfs_tpm2_sys_context,
					      TPM_RH_NULL, TPM_RH_NULL, NULL,
					      &nonce_caller, &salt,
					      type, &symmetric,
					      hash_alg, &s->session_handle,
					      &nonce_tpm, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to create a %spolicy session "
                    "(%#x)\n", type == TPM_SE_TRIAL ? "trial " : "",
		    rc);
                return -1;
        }

	dbg("The %spolicy session handle %#8.8x created\n",
	    type == TPM_SE_TRIAL ? "trial " : "",
	    s->session_handle);

	return 0;
}

void
policy_session_destroy(struct session_complex *s)
{
	UINT32 rc = Tss2_Sys_FlushContext(cryptfs_tpm2_sys_context,
					  s->session_handle);
	if (rc == TPM_RC_SUCCESS)
		dbg("The policy session %#8.8x destroyed\n", s->session_handle);
	else
		err("Unable to destroy the policy session handle "
		    "(%#x)\n", rc);
}

void
password_session_create(struct session_complex *s, char *auth_password)
{
	set_password_auth(&s->sessionData, auth_password);
	s->sessionDataArray[0] = &s->sessionData;
	s->sessionsData.cmdAuthsCount = 1;
	s->sessionsData.cmdAuths = s->sessionDataArray;

	s->sessionDataOutArray[0] = &s->sessionDataOut;
	s->sessionsDataOut.rspAuthsCount = 1;
	s->sessionsDataOut.rspAuths = s->sessionDataOutArray;
}