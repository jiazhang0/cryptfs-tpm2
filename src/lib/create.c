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
set_public(TPMI_ALG_PUBLIC type, TPMI_ALG_HASH name_alg, size_t passphrase_size,
	   TPM2B_PUBLIC *inPublic)
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

	*(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
	inPublic->t.publicArea.objectAttributes.restricted = 1;
	inPublic->t.publicArea.objectAttributes.userWithAuth = 1;
	inPublic->t.publicArea.objectAttributes.decrypt = 1;
	inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
	inPublic->t.publicArea.objectAttributes.fixedParent = 1;
	inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = !passphrase_size;
	inPublic->t.publicArea.authPolicy.t.size = 0;
	inPublic->t.publicArea.type = type;

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
		if (passphrase_size) {
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
cryptfs_tpm2_create_primary_key(char *auth_password)
{
	TPM2B_PUBLIC in_public;
	UINT32 rc;

	if (set_public(TPM_ALG_RSA, TPM_ALG_SHA256, 0, &in_public))
		return -1;

	TPM2B_SENSITIVE_CREATE in_sensitive;
	in_sensitive.t.sensitive.userAuth.t.size = strlen(CRYPTFS_TPM2_PRIMARY_KEY_SECRET);
	memcpy((char *)in_sensitive.t.sensitive.userAuth.t.buffer,
	       CRYPTFS_TPM2_PRIMARY_KEY_SECRET,
	       in_sensitive.t.sensitive.userAuth.t.size);

	in_sensitive.t.size = in_sensitive.t.sensitive.userAuth.b.size + 2;
	in_sensitive.t.sensitive.data.t.size = 0;

	TPML_PCR_SELECTION creation_pcr;
	creation_pcr.count = 0;

	TPM2B_DATA outside_info = { { 0, } };
	TPM2B_NAME out_name = { { sizeof(TPM2B_NAME)-2, } };
	TPM2B_PUBLIC out_public = { { 0, } };
	TPM2B_CREATION_DATA creation_data = { { 0, } };
	TPM2B_DIGEST creation_hash = { { sizeof(TPM2B_DIGEST)-2, } };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM_HANDLE obj_handle;

	struct session_complex s;
	session_init(&s, auth_password);

	rc = Tss2_Sys_CreatePrimary(cryptfs_tpm2_sys_context, TPM_RH_OWNER,
				    &s.sessionsData, &in_sensitive, &in_public,
				    &outside_info, &creation_pcr, &obj_handle,
				    &out_public, &creation_data, &creation_hash,
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
			       char *auth_password)
{
	TPM2B_PUBLIC in_public;
	UINT32 rc;

	passphrase_size = (passphrase && passphrase_size) ? passphrase_size : 0;

	if (set_public(TPM_ALG_KEYEDHASH, TPM_ALG_SHA256, passphrase_size,
		       &in_public))
		return -1;

	TPM2B_SENSITIVE_CREATE in_sensitive;
	in_sensitive.t.sensitive.userAuth.t.size = strlen(CRYPTFS_TPM2_PASSPHRASE_SECRET);
	memcpy(in_sensitive.t.sensitive.userAuth.t.buffer,
	       CRYPTFS_TPM2_PASSPHRASE_SECRET,
	       in_sensitive.t.sensitive.userAuth.t.size);

	in_sensitive.t.size = in_sensitive.t.sensitive.userAuth.b.size + 2;
	if (passphrase_size) {
		in_sensitive.t.sensitive.data.t.size = passphrase_size;
		memcpy(in_sensitive.t.sensitive.data.t.buffer, passphrase,
		       passphrase_size);
	} else
		in_sensitive.t.sensitive.data.t.size = 0;

	TPML_PCR_SELECTION creation_pcr;
	creation_pcr.count = 0;

	TPM2B_DATA outside_info = { { 0, } };
	TPM2B_CREATION_DATA creation_data = { { 0, } };
	TPM2B_DIGEST creation_hash = { { sizeof(TPM2B_DIGEST)-2, } };
	TPMT_TK_CREATION creation_ticket = { 0, };
	TPM2B_PUBLIC out_public = { { 0, } };
	TPM2B_PRIVATE out_private = { { sizeof(TPM2B_PRIVATE)-2, } };

	struct session_complex s;
	session_init(&s, CRYPTFS_TPM2_PRIMARY_KEY_SECRET);

	rc = Tss2_Sys_Create(cryptfs_tpm2_sys_context, CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
			     &s.sessionsData, &in_sensitive, &in_public,
			     &outside_info, &creation_pcr, &out_private,
			     &out_public, &creation_data, &creation_hash,
			     &creation_ticket, &s.sessionsDataOut);
	if (rc != TPM_RC_SUCCESS) {
        	err("Unable to create the passphrase object (%#x)\n", rc);
		return -1;
	}

	TPM2B_NAME name_ext = { { sizeof(TPM2B_NAME)-2, } };
	TPM_HANDLE obj_handle;

	rc = Tss2_Sys_Load(cryptfs_tpm2_sys_context, CRYPTFS_TPM2_PRIMARY_KEY_HANDLE,
			   &s.sessionsData, &out_private, &out_public, &obj_handle,
			   &name_ext, &s.sessionsDataOut);
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