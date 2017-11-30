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
 *        Lans Zhang <jia.zhang@windriver.com>
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
	session->nonce.size = 0;
	*((UINT8 *)((void *)&session->sessionAttributes)) = 0;
	session->sessionAttributes |= TPMA_SESSION_CONTINUESESSION;

	if (auth_password && auth_password_size) {
		session->hmac.size = auth_password_size;
		memcpy(session->hmac.buffer, auth_password,
		       session->hmac.size);
	} else
		session->hmac.size = 0;
}

static void
set_password_auth(TPMS_AUTH_COMMAND *session, char *auth_password,
		  unsigned int auth_password_size)
{
	set_session_auth(session, TPM2_RS_PW, auth_password,
			 auth_password && auth_password_size ?
			 auth_password_size : 0);
}

/* TODO: move this call to policy_session_create() */
void
policy_auth_set(TPMS_AUTH_COMMAND *session, TPMI_SH_AUTH_SESSION handle,
		char *auth_password, unsigned int auth_password_size)
{
	set_session_auth(session, handle, auth_password,
			 auth_password && auth_password_size ?
			 auth_password_size : 0);
}

/*
 * Create an unsalted and unbound policy session for generating
 * the policy digest calculated by TPM.
 */
int
policy_session_create(struct session_complex *s, TPM2_SE type,
		      TPMI_ALG_HASH hash_alg)
{
	UINT16 hash_alg_size;

	if (util_digest_size(hash_alg, &hash_alg_size))
		return -1;

	if (type != TPM2_SE_POLICY && type != TPM2_SE_TRIAL) {
		err("Invalid policy session type %#x specified\n", type);
		return -1;
	}

	TPM2B_ENCRYPTED_SECRET salt;
	salt.size = 0;

	/* No symmetric algorithm */
	TPMT_SYM_DEF symmetric;
	symmetric.algorithm = TPM2_ALG_NULL;

	TPM2B_NONCE nonce_caller;
	nonce_caller.size = hash_alg_size;
	memset(nonce_caller.buffer, 0, nonce_caller.size);

	TPM2B_NONCE nonce_tpm;
	nonce_tpm.size = nonce_caller.size;

	UINT32 rc = Tss2_Sys_StartAuthSession(cryptfs_tpm2_sys_context,
					      TPM2_RH_NULL, TPM2_RH_NULL, NULL,
					      &nonce_caller, &salt,
					      type, &symmetric,
					      hash_alg, &s->session_handle,
					      &nonce_tpm, NULL);
	if (rc != TPM2_RC_SUCCESS) {
		err("Unable to create a %spolicy session "
		    "(%#x)\n", type == TPM2_SE_TRIAL ? "trial " : "",
		    rc);
		return -1;
	}

	complete_session_complex(s);

	dbg("The %spolicy session handle %#8.8x created\n",
	    type == TPM2_SE_TRIAL ? "trial " : "",
	    s->session_handle);

	return 0;
}

void
policy_session_destroy(struct session_complex *s)
{
	if (s->session_handle == TPM2_RS_PW)
		return;

	UINT32 rc = Tss2_Sys_FlushContext(cryptfs_tpm2_sys_context,
					  s->session_handle);
	if (rc == TPM2_RC_SUCCESS)
		dbg("The policy session %#8.8x destroyed\n", s->session_handle);
	else
		err("Unable to destroy the policy session handle "
		    "(%#x)\n", rc);
}

void
password_session_create(struct session_complex *s, char *auth_password,
			unsigned int auth_password_size)
{
	set_password_auth(&s->sessionData, auth_password, auth_password_size);

	s->session_handle = TPM2_RS_PW;

	complete_session_complex(s);
}
