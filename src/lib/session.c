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
complete_session_complex(struct session_complex *s)
{
	s->sessionDataArray[0] = &s->sessionData;
	s->sessionsData.cmdAuthsCount = 1;
	s->sessionsData.cmdAuths = s->sessionDataArray;

	s->sessionDataOutArray[0] = &s->sessionDataOut;
	s->sessionsDataOut.rspAuthsCount = 1;
	s->sessionsDataOut.rspAuths = s->sessionDataOutArray;
}

static void
set_session_auth(TPMS_AUTH_COMMAND *session, TPMI_SH_AUTH_SESSION handle,
		 void *auth_password, size_t auth_password_size)
{
	session->sessionHandle = handle;
	session->nonce.t.size = 0;
	*((UINT8 *)((void *)&session->sessionAttributes)) = 0;

	if (auth_password && auth_password_size) {
		session->hmac.t.size = auth_password_size;
		memcpy(session->hmac.t.buffer, auth_password,
		       session->hmac.t.size);
	} else
		session->hmac.t.size = 0;
}

static void
set_password_auth(TPMS_AUTH_COMMAND *session, char *auth_password)
{
	set_session_auth(session, TPM_RS_PW, auth_password,
			 auth_password ? strlen(auth_password) : 0);
}

/* TODO: move this call to policy_session_create() */
void
policy_auth_set(TPMS_AUTH_COMMAND *session, TPMI_SH_AUTH_SESSION handle,
		char *auth_password)
{
	set_session_auth(session, handle, auth_password,
			 auth_password ? strlen(auth_password) : 0);
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
		err("Invalid policy session type %#x specified\n", type);
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

	complete_session_complex(s);

	dbg("The %spolicy session handle %#8.8x created\n",
	    type == TPM_SE_TRIAL ? "trial " : "",
	    s->session_handle);

	return 0;
}

void
policy_session_destroy(struct session_complex *s)
{
	if (s->session_handle == TPM_RS_PW)
		return;

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

	s->session_handle = TPM_RS_PW;

	complete_session_complex(s);
}