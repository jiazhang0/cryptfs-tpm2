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

static int
calc_policy_digest(TPML_PCR_SELECTION *pcrs, TPMI_ALG_HASH policy_digest_alg,
		   TPM2B_DIGEST *policy_digest)
{
	if (util_digest_size(policy_digest_alg, &policy_digest->size))
		return -1;

	struct session_complex s;

	if (policy_session_create(&s, TPM2_SE_TRIAL, policy_digest_alg))
		return -1;

	if (pcr_policy_extend(s.session_handle, pcrs, policy_digest_alg)) {
		policy_session_destroy(&s);
		return -1;
	}

	if (password_policy_extend(s.session_handle)) {
		policy_session_destroy(&s);
		return -1;
	}

	UINT32 rc = Tss2_Sys_PolicyGetDigest(cryptfs_tpm2_sys_context,
					     s.session_handle, NULL,
					     policy_digest, NULL);
	policy_session_destroy(&s);
	if (rc != TPM2_RC_SUCCESS) {
		err("Unable to get the policy digest (%#x)\n", rc);
		return -1;
	}

	return 0;
}

static int
set_public(TPMI_ALG_PUBLIC type, TPMI_ALG_HASH name_alg, int set_key,
	   size_t sensitive_size, TPM2B_PUBLIC *inPublic,
	   TPM2B_DIGEST *policy_digest)
{
	switch (name_alg) {
	case TPM2_ALG_SHA1:
	case TPM2_ALG_SHA256:
	case TPM2_ALG_SHA384:
	case TPM2_ALG_SHA512:
	case TPM2_ALG_SM3_256:
	case TPM2_ALG_NULL:
		inPublic->publicArea.nameAlg = name_alg;
		break;
	default:
		err("nameAlg algorithm %#x is not supportted\n", name_alg);
		return -1;
	}

	int use_policy = 0;

	if (policy_digest && policy_digest->size) {
		UINT16 name_alg_size;

		if (util_digest_size(name_alg, &name_alg_size))
			return -1;

		if (policy_digest->size < name_alg_size) {
			err("The size of policy digest (%d-byte) should be "
			    "equal or bigger then nameAlg (%d-byte)\n",
			    policy_digest->size, name_alg_size);
			return -1;
		}

		use_policy = 1;
	}

	*(UINT32 *)&(inPublic->publicArea.objectAttributes) = 0;
	inPublic->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
	if (set_key || !use_policy)
		inPublic->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
	inPublic->publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
	inPublic->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
	inPublic->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
	if (!sensitive_size)
		inPublic->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	if (option_no_da)
		inPublic->publicArea.objectAttributes |= TPMA_OBJECT_NODA;
	inPublic->publicArea.type = type;

	if (use_policy)
		inPublic->publicArea.authPolicy = *policy_digest;
	else
		inPublic->publicArea.authPolicy.size = 0;

	switch (type) {
	case TPM2_ALG_RSA:
		inPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
		inPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
		inPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		inPublic->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		inPublic->publicArea.parameters.rsaDetail.keyBits = 2048;
		inPublic->publicArea.parameters.rsaDetail.exponent = 0;
		inPublic->publicArea.unique.rsa.size = 0;
		break;
	case TPM2_ALG_KEYEDHASH:
		if (!set_key) {
			/* Always used for sealed data */
			inPublic->publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
			inPublic->publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
			inPublic->publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT ;
			inPublic->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
		} else {
			inPublic->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_XOR;
			inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM2_ALG_SHA256;
			inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM2_ALG_KDF1_SP800_108;
		}
		inPublic->publicArea.unique.keyedHash.size = 0;
		break;
	case TPM2_ALG_ECC:
		inPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
		inPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
		inPublic->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
		inPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		inPublic->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
		inPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		inPublic->publicArea.unique.ecc.x.size = 0;
		inPublic->publicArea.unique.ecc.y.size = 0;
		break;
	case TPM2_ALG_SYMCIPHER:
		inPublic->publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
		inPublic->publicArea.parameters.symDetail.sym.keyBits.sym = 128;
		inPublic->publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
		inPublic->publicArea.unique.sym.size = 0;
		break;
	default:
		err("type algorithm %#x is not supportted\n", type);
		return -1;
	}

	return 0;
}

int
cryptfs_tpm2_create_primary_key(TPMI_ALG_HASH pcr_bank_alg)
{
	TPML_PCR_SELECTION creation_pcrs;
	TPM2B_DIGEST policy_digest;
	TPMI_ALG_HASH name_alg;

	if (pcr_bank_alg != TPM2_ALG_NULL) {
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		creation_pcrs.count = 1;
		creation_pcrs.pcrSelections->hash = pcr_bank_alg;
		creation_pcrs.pcrSelections->sizeofSelect = 3;
		memset(creation_pcrs.pcrSelections->pcrSelect, 0,
		       TPM2_PCR_SELECT_MAX);
		creation_pcrs.pcrSelections->pcrSelect[pcr_index / 8] |=
			(1 << (pcr_index % 8));

		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;
		if (calc_policy_digest(&creation_pcrs, policy_digest_alg,
				       &policy_digest))
			return -1;

		name_alg = pcr_bank_alg;
	} else {
		creation_pcrs.count = 0;
		policy_digest.size = 0;
		name_alg = TPM2_ALG_SHA1;
	}

	TPM2B_PUBLIC in_public;
	if (set_public(TPM2_ALG_RSA, name_alg, 1, 0, &in_public,
		       &policy_digest))
		return -1;

	char secret[CRYPTFS_TPM2_SECRET_MAX_SIZE];
	unsigned int secret_size = sizeof(secret);

	get_primary_key_secret(secret, &secret_size);

	TPM2B_SENSITIVE_CREATE in_sensitive;

	in_sensitive.sensitive.userAuth.size = secret_size;
	memcpy((char *)in_sensitive.sensitive.userAuth.buffer,
	       secret, in_sensitive.sensitive.userAuth.size);
	in_sensitive.size = in_sensitive.sensitive.userAuth.size + 2;
	in_sensitive.sensitive.data.size = 0;

	TPM2B_DATA outside_info = { 0, };
	TPM2B_NAME out_name = { sizeof(TPM2B_NAME) - 2, };
	TPM2B_PUBLIC out_public = { 0, };
	TPM2B_CREATION_DATA creation_data = { 0, };
	TPM2B_DIGEST creation_hash = { sizeof(TPM2B_DIGEST) - 2, };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM2_HANDLE obj_handle;
	uint8_t owner_auth[sizeof(TPMU_HA)];
	unsigned int owner_auth_size = sizeof(owner_auth);

	cryptfs_tpm2_option_get_owner_auth(owner_auth, &owner_auth_size);

	struct session_complex s;
	UINT32 rc;

redo:
	password_session_create(&s, (char *)owner_auth, owner_auth_size);

	rc = Tss2_Sys_CreatePrimary(cryptfs_tpm2_sys_context,
				    TPM2_RH_OWNER, &s.sessionsData,
				    &in_sensitive, &in_public,
				    &outside_info, &creation_pcrs,
				    &obj_handle, &out_public,
				    &creation_data, &creation_hash,
				    &creation_ticket, &out_name,
				    &s.sessionsDataOut);
	if (rc != TPM2_RC_SUCCESS) {
		if (rc == TPM2_RC_LOCKOUT) {
			if (da_reset() == EXIT_SUCCESS)
				goto redo;
		} else if (tpm2_rc_is_format_one(rc) &&
			   (tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_BAD_AUTH) {
			owner_auth_size = sizeof(owner_auth);

			if (cryptfs_tpm2_util_get_owner_auth(owner_auth,
							     &owner_auth_size) ==
							     EXIT_SUCCESS)
				goto redo;
		}

        	err("Unable to create and load the primary key "
		    "(%#x)\n", rc);
		return -1;
	}

	/* Avoid typing the owner authentication again */
	/* XXX: only set owner authentication in this way if
	 * the authentication check really fails with
	 * Tss2_Sys_CreatePrimary().
	 */
	cryptfs_tpm2_option_set_owner_auth(owner_auth, &owner_auth_size);

	dbg("Preparing to persist the primary key object ...\n");

	rc = cryptfs_tpm2_persist_primary_key(obj_handle);
	if (rc != TPM2_RC_SUCCESS) {
        	err("Unable to persist the primary key\n");
		return -1;
	}

	info("Succeed to create and load the primary key with the "
	     "handle value: %#8.8x\n", obj_handle);

	return 0;
}

int
cryptfs_tpm2_create_passphrase(char *passphrase, size_t passphrase_size,
			       TPMI_ALG_HASH pcr_bank_alg)
{
	TPML_PCR_SELECTION creation_pcrs;
	TPM2B_DIGEST policy_digest;
	TPMI_ALG_HASH name_alg;
	char fixed_passphrase[CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE];

	if (pcr_bank_alg != TPM2_ALG_NULL) {
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		creation_pcrs.count = 1;
		creation_pcrs.pcrSelections->hash = pcr_bank_alg;
		creation_pcrs.pcrSelections->sizeofSelect = 3;
		memset(creation_pcrs.pcrSelections->pcrSelect, 0,
		       TPM2_PCR_SELECT_MAX);
		creation_pcrs.pcrSelections->pcrSelect[pcr_index / 8] |=
			(1 << (pcr_index % 8));

		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;
		if (calc_policy_digest(&creation_pcrs, policy_digest_alg,
				       &policy_digest))
			return -1;

		name_alg = pcr_bank_alg;
	} else {
		creation_pcrs.count = 0;
		policy_digest.size = 0;
		name_alg = TPM2_ALG_SHA1;
	}

	UINT32 rc;

	passphrase_size = (passphrase && passphrase_size) ?
			  passphrase_size : 0;
	if (!passphrase_size) {
		/*
		 * The sealed data (decrypt == 0 and sign == 0) must not
		 * be empty otherwise TPM2_RC_ATTRIBUTES will be returned.
		 */
		passphrase_size = CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE;
		rc = cryptefs_tpm2_get_random((uint8_t *)fixed_passphrase,
					      &passphrase_size);
		if (rc != TPM2_RC_SUCCESS || !passphrase_size) {
			err("Unable to generate random for passphrase "
			    "(%#x)\n", rc);
			return -1;
		}

		passphrase = fixed_passphrase;
	}

	TPM2B_PUBLIC in_public;

	if (set_public(TPM2_ALG_KEYEDHASH, name_alg, 0, passphrase_size,
		       &in_public, &policy_digest))
		return -1;

	char secret[CRYPTFS_TPM2_SECRET_MAX_SIZE];
	unsigned int secret_size = sizeof(secret);

	get_passphrase_secret(secret, &secret_size);

	TPM2B_SENSITIVE_CREATE in_sensitive;

	in_sensitive.sensitive.userAuth.size = secret_size;
	memcpy(in_sensitive.sensitive.userAuth.buffer,
	       secret, in_sensitive.sensitive.userAuth.size);
	in_sensitive.size = in_sensitive.sensitive.userAuth.size + 2;
	in_sensitive.sensitive.data.size = passphrase_size;
	memcpy(in_sensitive.sensitive.data.buffer, passphrase,
	       passphrase_size);

	TPM2B_DATA outside_info = { 0, };
	TPM2B_CREATION_DATA creation_data = { 0, };
	TPM2B_DIGEST creation_hash = { sizeof(TPM2B_DIGEST) - 2, };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM2B_PUBLIC out_public = { 0, };
	TPM2B_PRIVATE out_private = { sizeof(TPM2B_PRIVATE) - 2, };
	struct session_complex s;

re_auth_pkey:
	secret_size = sizeof(secret);
	get_primary_key_secret(secret, &secret_size);
redo:
	password_session_create(&s, (char *)secret, secret_size);

	rc = Tss2_Sys_Create(cryptfs_tpm2_sys_context,
			     CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
			     &s.sessionsData, &in_sensitive, &in_public,
			     &outside_info, &creation_pcrs,
			     &out_private, &out_public, &creation_data,
			     &creation_hash, &creation_ticket,
			     &s.sessionsDataOut);
	if (rc != TPM2_RC_SUCCESS) {
		if (rc == TPM2_RC_LOCKOUT) {
			if (da_reset() == EXIT_SUCCESS)
				goto re_auth_pkey;
		} else if (tpm2_rc_is_format_one(rc) &&
			   (((tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_BAD_AUTH) ||
			   ((tpm2_rc_get_code_7bit(rc) | TPM2_RC_FMT1) ==
			   TPM2_RC_AUTH_FAIL))) {
			err("Wrong primary key secret specified\n");

			secret_size = sizeof(secret);

			if (cryptfs_tpm2_util_get_primary_key_secret((uint8_t *)secret,
								     &secret_size) ==
			    EXIT_SUCCESS)
				goto redo;
		}

        	err("Unable to create the passphrase object (%#x)\n", rc);
		return -1;
	}

	dbg("Preparing to load the passphrase object ...\n");

	TPM2B_NAME name_ext = { sizeof(TPM2B_NAME) - 2, };
	TPM2_HANDLE obj_handle;

	rc = Tss2_Sys_Load(cryptfs_tpm2_sys_context,
			   CRYPTFS_TPM2_PRIMARY_KEY_HANDLE, &s.sessionsData,
			   &out_private, &out_public, &obj_handle, &name_ext,
			   &s.sessionsDataOut);
	if (rc != TPM2_RC_SUCCESS) {
        	err("Unable to load the passphrase object (%#x)\n", rc);
		return -1;
	}

	dbg("Preparing to persiste the passphrase object ...\n");

	/* XXX: check whether already persisted. TPM2_RC_NV_DEFINED (0x14c) */
	rc = cryptfs_tpm2_persist_passphrase(obj_handle);
	if (rc != TPM2_RC_SUCCESS) {
		err("Unable to persist the passphrase object\n");
		return -1;
	}

	info("Succeed to create and load the passphrase object with the "
	     "handle value: %#8.8x\n", obj_handle);

	return 0;
}
