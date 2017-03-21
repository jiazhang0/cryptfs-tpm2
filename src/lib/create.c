/*
 * Object creation
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

static int
calc_policy_digest(TPML_PCR_SELECTION *pcrs, TPMI_ALG_HASH policy_digest_alg,
		   TPM2B_DIGEST *policy_digest)
{
	if (util_digest_size(policy_digest_alg, &policy_digest->t.size))
		return -1;

	struct session_complex s;

	if (policy_session_create(&s, TPM_SE_TRIAL, policy_digest_alg))
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
	if (rc != TPM_RC_SUCCESS) {
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
	case TPM_ALG_SHA1:
	case TPM_ALG_SHA256:
	case TPM_ALG_SHA384:
	case TPM_ALG_SHA512:
	case TPM_ALG_SM3_256:
	case TPM_ALG_NULL:
		inPublic->t.publicArea.nameAlg = name_alg;
		break;
	default:
		err("nameAlg algorithm %#x is not supportted\n", name_alg);
		return -1;
	}

	int use_policy = 0;

	if (policy_digest && policy_digest->t.size) {
		UINT16 name_alg_size;

		if (util_digest_size(name_alg, &name_alg_size))
			return -1;

		if (policy_digest->t.size < name_alg_size) {
			err("The size of policy digest (%d-byte) should be "
			    "equal or bigger then nameAlg (%d-byte)\n",
			    policy_digest->t.size, name_alg_size);
			return -1;
		}

		use_policy = 1;
	}

	*(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
	inPublic->t.publicArea.objectAttributes.restricted = 1;
	inPublic->t.publicArea.objectAttributes.userWithAuth = set_key ? 1: !use_policy;
	inPublic->t.publicArea.objectAttributes.decrypt = 1;
	inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
	inPublic->t.publicArea.objectAttributes.fixedParent = 1;
	inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = !sensitive_size;
	inPublic->t.publicArea.type = type;

	if (use_policy)
		inPublic->t.publicArea.authPolicy = *policy_digest;
	else
		inPublic->t.publicArea.authPolicy.t.size = 0;

	switch (type) {
	case TPM_ALG_RSA:
		inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
		inPublic->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
		inPublic->t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
		inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
		inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
		inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
		inPublic->t.publicArea.unique.rsa.t.size = 0;
		break;
	case TPM_ALG_KEYEDHASH:
		if (!set_key) {
			/* Always used for sealed data */
			inPublic->t.publicArea.objectAttributes.sign = 0;
			inPublic->t.publicArea.objectAttributes.restricted = 0;
			inPublic->t.publicArea.objectAttributes.decrypt = 0;
			inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
		} else {
			inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
			inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_SHA256;
			inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
		}
		inPublic->t.publicArea.unique.keyedHash.t.size = 0;
		break;
	case TPM_ALG_ECC:
		inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
		inPublic->t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
		inPublic->t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
		inPublic->t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
		inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
		inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		inPublic->t.publicArea.unique.ecc.x.t.size = 0;
		inPublic->t.publicArea.unique.ecc.y.t.size = 0;
		break;
	case TPM_ALG_SYMCIPHER:
		inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
		inPublic->t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
		inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
		inPublic->t.publicArea.unique.sym.t.size = 0;
		break;
	default:
		err("type algorithm %#x is not supportted\n", type);
		return -1;
	}

	return 0;
}

int
cryptfs_tpm2_create_primary_key(TPMI_ALG_HASH pcr_bank_alg,
				char *auth_password)
{
	TPML_PCR_SELECTION creation_pcrs;
	TPM2B_DIGEST policy_digest;
	TPMI_ALG_HASH name_alg;

	if (pcr_bank_alg != TPM_ALG_NULL) {
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		creation_pcrs.count = 1;
		creation_pcrs.pcrSelections->hash = pcr_bank_alg;
		creation_pcrs.pcrSelections->sizeofSelect = PCR_SELECT_MAX;
		memset(creation_pcrs.pcrSelections->pcrSelect, 0,
		       PCR_SELECT_MAX);
		creation_pcrs.pcrSelections->pcrSelect[pcr_index / 8] |=
			(1 << (pcr_index % 8));

		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;
		if (calc_policy_digest(&creation_pcrs, policy_digest_alg,
				       &policy_digest))
			return -1;

		name_alg = pcr_bank_alg;
	} else {
		creation_pcrs.count = 0;
		policy_digest.t.size = 0;
		name_alg = TPM_ALG_SHA1;
	}

	TPM2B_PUBLIC in_public;
	if (set_public(TPM_ALG_RSA, name_alg, 1, 0, &in_public,
		       &policy_digest))
		return -1;

	TPM2B_SENSITIVE_CREATE in_sensitive;
	in_sensitive.t.sensitive.userAuth.t.size =
		strlen(CRYPTFS_TPM2_PRIMARY_KEY_SECRET);
	memcpy((char *)in_sensitive.t.sensitive.userAuth.t.buffer,
	       CRYPTFS_TPM2_PRIMARY_KEY_SECRET,
	       in_sensitive.t.sensitive.userAuth.t.size);
	in_sensitive.t.size = in_sensitive.t.sensitive.userAuth.t.size + 2;
	in_sensitive.t.sensitive.data.t.size = 0;

	struct session_complex s;
	password_session_create(&s, auth_password);

	TPM2B_DATA outside_info = { { 0, } };
	TPM2B_NAME out_name = { { sizeof(TPM2B_NAME) - 2, } };
	TPM2B_PUBLIC out_public = { { 0, } };
	TPM2B_CREATION_DATA creation_data = { { 0, } };
	TPM2B_DIGEST creation_hash = { { sizeof(TPM2B_DIGEST) - 2, } };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM_HANDLE obj_handle;

	UINT32 rc = Tss2_Sys_CreatePrimary(cryptfs_tpm2_sys_context,
					   TPM_RH_OWNER, &s.sessionsData,
					   &in_sensitive, &in_public,
					   &outside_info, &creation_pcrs,
					   &obj_handle, &out_public,
					   &creation_data, &creation_hash,
					   &creation_ticket, &out_name,
					   &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to create and load the primary key "
		    "(%#x)\n", rc);
		return -1;
	}

	rc = cryptfs_tpm2_persist_primary_key(obj_handle, auth_password);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to persist the primary key\n");
		return -1;
	}

	info("Succeed to create and load the primary key with the "
	     "handle value: %#8.8x\n", obj_handle);

	return 0;
}

int
cryptfs_tpm2_create_passphrase(char *passphrase, size_t passphrase_size,
			       TPMI_ALG_HASH pcr_bank_alg,
			       char *auth_password)
{
	TPML_PCR_SELECTION creation_pcrs;
	TPM2B_DIGEST policy_digest;
	TPMI_ALG_HASH name_alg;
	TPM2B_DIGEST random_passphrase = { { sizeof(TPM2B_DIGEST) - 2, } };

	if (pcr_bank_alg != TPM_ALG_NULL) {
		unsigned int pcr_index = CRYPTFS_TPM2_PCR_INDEX;

		creation_pcrs.count = 1;
		creation_pcrs.pcrSelections->hash = pcr_bank_alg;
		creation_pcrs.pcrSelections->sizeofSelect = PCR_SELECT_MAX;
		memset(creation_pcrs.pcrSelections->pcrSelect, 0,
		       PCR_SELECT_MAX);
		creation_pcrs.pcrSelections->pcrSelect[pcr_index / 8] |=
			(1 << (pcr_index % 8));

		TPMI_ALG_HASH policy_digest_alg = pcr_bank_alg;
		if (calc_policy_digest(&creation_pcrs, policy_digest_alg,
				       &policy_digest))
			return -1;

		name_alg = pcr_bank_alg;
	} else {
		creation_pcrs.count = 0;
		policy_digest.t.size = 0;
		name_alg = TPM_ALG_SHA1;
	}

tpm2_create_errata_0x2c2:
	passphrase_size = (passphrase && passphrase_size) ?
			  passphrase_size : 0;
	TPM2B_PUBLIC in_public;
	if (set_public(TPM_ALG_KEYEDHASH, name_alg, 0, passphrase_size,
		       &in_public, &policy_digest))
		return -1;

	TPM2B_SENSITIVE_CREATE in_sensitive;
	in_sensitive.t.sensitive.userAuth.t.size =
		strlen(CRYPTFS_TPM2_PASSPHRASE_SECRET);
	memcpy(in_sensitive.t.sensitive.userAuth.t.buffer,
	       CRYPTFS_TPM2_PASSPHRASE_SECRET,
	       in_sensitive.t.sensitive.userAuth.t.size);
	in_sensitive.t.size = in_sensitive.t.sensitive.userAuth.t.size + 2;
	if (passphrase_size) {
		in_sensitive.t.sensitive.data.t.size = passphrase_size;
		memcpy(in_sensitive.t.sensitive.data.t.buffer, passphrase,
		       passphrase_size);
	} else
		in_sensitive.t.sensitive.data.t.size = 0;

	struct session_complex s;
	password_session_create(&s, CRYPTFS_TPM2_PRIMARY_KEY_SECRET);

	TPM2B_DATA outside_info = { { 0, } };
	TPM2B_CREATION_DATA creation_data = { { 0, } };
	TPM2B_DIGEST creation_hash = { { sizeof(TPM2B_DIGEST) - 2, } };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM2B_PUBLIC out_public = { { 0, } };
	TPM2B_PRIVATE out_private = { { sizeof(TPM2B_PRIVATE) - 2, } };

	UINT32 rc = Tss2_Sys_Create(cryptfs_tpm2_sys_context,
				    CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
				    &s.sessionsData, &in_sensitive, &in_public,
				    &outside_info, &creation_pcrs,
				    &out_private, &out_public, &creation_data,
				    &creation_hash, &creation_ticket,
				    &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
		/*
		 * Work around the 0x2c2 error code for certain TPM device
		 * such as Intel fTPM.
		 */
		if (rc == (TPM_RC_ATTRIBUTES | TPM_RC_P | TPM_RC_2) &&
		    !passphrase_size) {
			rc = Tss2_Sys_GetRandom(cryptfs_tpm2_sys_context, NULL,
						CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE,
						&random_passphrase, NULL);
			if (rc != TPM_RC_SUCCESS) {
				err("Unable to generate random for passphrase "
				    "(%#x)\n", rc);
				return -1;
			}

			passphrase = (char *)random_passphrase.t.buffer;
			passphrase_size = random_passphrase.t.size;

			cryptfs_tpm2_util_hex_dump("TPM2 RNG passphrase",
						   (uint8_t *)passphrase,
						   passphrase_size);
			goto tpm2_create_errata_0x2c2;
		}

        	err("Unable to create the passphrase object (%#x)\n", rc);
		return -1;
	}

	TPM2B_NAME name_ext = { { sizeof(TPM2B_NAME) - 2, } };
	TPM_HANDLE obj_handle;

	rc = Tss2_Sys_Load(cryptfs_tpm2_sys_context,
			   CRYPTFS_TPM2_PRIMARY_KEY_HANDLE, &s.sessionsData,
			   &out_private, &out_public, &obj_handle, &name_ext,
			   &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to load the passphrase object (%#x)\n", rc);
		return -1;
	}

	/* TODO: check whether already persisted. TPM_RC_NV_DEFINED (0x14c) */
	rc = cryptfs_tpm2_persist_passphrase(obj_handle, auth_password);
	if (rc) {
		err("Unable to persist the passphrase object\n");
		return -1;
	}

	info("Succeed to create and load the passphrase object with the "
	     "handle value: %#8.8x\n", obj_handle);

	return 0;
}
