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

typedef struct {
	TPMI_ALG_HASH alg;
	unsigned int weight;
} digest_alg_weight_t;

int
capability_read_public(TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public_out)
{
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA capability_data;

	UINT32 rc = Tss2_Sys_GetCapability(cryptfs_tpm2_sys_context, NULL,
					   TPM_CAP_HANDLES, TPM_HT_PERSISTENT,
          				   TPM_PT_HR_PERSISTENT, &more_data,
					   &capability_data, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to get the TPM persistent handles (%#x)", rc);
		return -1;
	};

	dbg("%d persistent objects detected:\n", capability_data.data.handles.count);
	for (UINT32 i = 0; i < capability_data.data.handles.count; ++i) {
		TPMI_DH_OBJECT h = capability_data.data.handles.handle[i];

        	dbg_cont("  [%02d] %#8.8x\n", i, h);

		if (h != handle)
			continue;

        	/* Actually TPM2_ReadPublic doesn't require any authorization */
        	struct session_complex s;
		password_session_create(&s, NULL, 0);

		TPM2B_NAME name = { { sizeof(TPM2B_NAME)-2, } };
		TPM2B_NAME qualified_name = { { sizeof(TPM2B_NAME)-2, } };

		rc = Tss2_Sys_ReadPublic(cryptfs_tpm2_sys_context, handle,
					 NULL, public_out, &name,
					 &qualified_name, &s.sessionsDataOut);
		if (rc != TPM_RC_SUCCESS) {
			err("Unable to read the public area for the "
			    "persistent handle %#8.8x (%#x)", handle, rc);
			return -1;
		}

		return 0;
	}

	return -1;
}

static unsigned int
weight_digest_algorithm(TPMI_ALG_HASH hash_alg)
{
	digest_alg_weight_t alg_list[] = {
		{
			TPM_ALG_SHA1,
			SHA1_DIGEST_SIZE
		},
		{
			TPM_ALG_SHA256,
			SHA256_DIGEST_SIZE
		},
		{
			TPM_ALG_SHA384,
			SHA384_DIGEST_SIZE
		},
		{
			TPM_ALG_SHA512,
			SHA512_DIGEST_SIZE
		},
		{
			TPM_ALG_SM3_256,
			SM3_256_DIGEST_SIZE + 5
		},
		{
			TPM_ALG_NULL,
			0
		}
	};

	for (unsigned int i = 0; alg_list[i].alg != TPM_ALG_NULL; ++i) {
		if (hash_alg == alg_list[i].alg)
			return alg_list[i].weight;
	}

	return 0;
}

static unsigned int
digest_algorithm_base_weight(TPMI_ALG_HASH hash_alg)
{
	switch (hash_alg) {
	case TPM_ALG_SHA1:
		return 1;
	case TPM_ALG_SHA256:
		return 2;
	case TPM_ALG_SM3_256:
		return 3;
	case TPM_ALG_SHA384:
		return 7;
	case TPM_ALG_SHA512:
		return 9;
	case TPM_ALG_NULL:
	default:
		break;
	}

	return 0;
}

static const char *
show_algorithm_name(TPM_ALG_ID alg)
{
	switch (alg) {
	case TPM_ALG_RSA:
		return "RSA";
	case TPM_ALG_SHA1:
		return "SHA-1";
	case TPM_ALG_HMAC:
		return "HMAC";
	case TPM_ALG_AES:
		return "AES";
	case TPM_ALG_MGF1:
		return "MGF1";
	case TPM_ALG_KEYEDHASH:
		return "KEYEDHASH";
	case TPM_ALG_XOR:
		return "XOR";
	case TPM_ALG_SHA256:
		return "SHA-256";
	case TPM_ALG_SHA384:
		return "SHA-384";
	case TPM_ALG_SHA512:
		return "SHA-512";
	case TPM_ALG_NULL:
		return "NULL";
	case TPM_ALG_SM3_256:
		return "SM3-256";
	case TPM_ALG_SM4:
		return "SM4";
	case TPM_ALG_RSASSA:
		return "RSASSA PKCS#1 v1.5";
	case TPM_ALG_RSAES:
		return "RSAES PKCS#1 v1.5";
	case TPM_ALG_RSAPSS:
		return "RSAES PSS";
	case TPM_ALG_OAEP:
		return "RSAES OAEP";
	case TPM_ALG_ECDSA:
		return "ECDSA";
	case TPM_ALG_ECDH:
		return "ECC CDH";
	case TPM_ALG_SM2:
		return "SM2";
	case TPM_ALG_ECSCHNORR:
		return "ECS";
	case TPM_ALG_KDF1_SP800_56A:
		return "KDF1 (NIST SP800-56A)";
	case TPM_ALG_KDF1_SP800_108:
		return "KDF1 (NIST SP800-108)";
	case TPM_ALG_ECC:
		return "ECC";
	case TPM_ALG_SYMCIPHER:
		return "Symmetric block cipher";
	case TPM_ALG_CTR:
		return "Symmetric block cipher (Counter mode)";
	case TPM_ALG_OFB:
		return "Symmetric block cipher (Output Feedback mode)";
	case TPM_ALG_CBC:
		return "Symmetric block cipher (Cipher Block Chaining mode)";
	case TPM_ALG_CFB:
		return "Symmetric block cipher (Cipher Feedback mode)";
	case TPM_ALG_ECB:
		return "Symmetric block cipher (Electronic Codebook mode)";
	case TPM_ALG_ERROR:
		return NULL;
	case 0x00c1 ... 0x00c6:
		return "Reserved (for TPM 1.2 tags conflict)";
	case 0x8000 ... 0xffff:
		return "Reserved (for other structure tags)";
	}

	return NULL;
}

static bool
is_null_hash(BYTE *hash, unsigned int hash_size)
{
	for (unsigned int i = 0; i < hash_size; ++i) {
		if (hash[i])
			return false;
	}

	return true;
}

bool
cryptfs_tpm2_capability_digest_algorithm_supported(TPMI_ALG_HASH *hash_alg)
{
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA capability_data;
	UINT32 rc;

	rc = Tss2_Sys_GetCapability(cryptfs_tpm2_sys_context, NULL,
				    TPM_CAP_ALGS, TPM_PT_NONE, 1, &more_data,
				    &capability_data, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to get the TPM supported algorithms (%#x)", rc);
		return false;
	};

	TPML_ALG_PROPERTY *algs = &capability_data.data.algorithms;
	unsigned int i;

#ifdef DEBUG
	dbg("%d algorithms detected: ", algs->count);

	for (i = 0; i < algs->count; ++i)
		dbg_cont("%s ",
			 show_algorithm_name(algs->algProperties[i].alg));

	dbg_cont("\n");
#endif

	TPMI_ALG_HASH preferred_alg = TPM_ALG_NULL;
	unsigned int weight = 0;

	for (i = 0; i < algs->count; ++i) {
		TPMS_ALG_PROPERTY alg_property = algs->algProperties[i];
		unsigned alg_weight;

		if (alg_property.algProperties.hash != 1)
			continue;

		if (*hash_alg == alg_property.alg)
			return true;

		alg_weight = weight_digest_algorithm(alg_property.alg);
		if (alg_weight > weight) {
			weight = alg_weight;
			preferred_alg = alg_property.alg;
		}
	}

	if (*hash_alg != TPM_ALG_AUTO)
		return false;

	if (preferred_alg == TPM_ALG_NULL)
		return false;

	*hash_alg = preferred_alg;

	return true;
}

bool
cryptfs_tpm2_capability_pcr_bank_supported(TPMI_ALG_HASH *hash_alg)
{
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA capability_data;
	UINT32 rc;

	rc = Tss2_Sys_GetCapability(cryptfs_tpm2_sys_context, NULL,
				    TPM_CAP_PCRS, TPM_PT_NONE, 1, &more_data,
				    &capability_data, NULL);
	if (rc != TPM_RC_SUCCESS) {
		err("Unable to get the TPM PCR banks (%#x)", rc);
		return false;
	}

	unsigned int i;
	TPML_PCR_SELECTION *banks = &capability_data.data.assignedPCR;

#ifdef DEBUG
	dbg("%d PCR banks detected: ", banks->count);

	for (i = 0; i < banks->count; ++i)
		dbg_cont("%s ",
			 show_algorithm_name(banks->pcrSelections[i].hash));

	dbg_cont("\n");
#endif

	TPMI_ALG_HASH preferred_alg = TPM_ALG_NULL;
	unsigned int weight = 0;

	for (i = 0; i < banks->count; ++i) {
		TPMI_ALG_HASH bank_alg;

		bank_alg = banks->pcrSelections[i].hash;
		if (*hash_alg == bank_alg)
			return true;

		if (*hash_alg != TPM_ALG_AUTO)
			continue;

		unsigned int alg_weight;

		alg_weight = weight_digest_algorithm(bank_alg);

		UINT16 alg_size;

		util_digest_size(bank_alg, &alg_size);

		BYTE pcr_value[alg_size];

		rc = cryptfs_tpm2_read_pcr(bank_alg,
					   CRYPTFS_TPM2_PCR_INDEX,
					   pcr_value);
		if (rc != TPM_RC_SUCCESS)
			continue;

		if (is_null_hash(pcr_value, alg_size)) {
			warn("%s PCR bank is unused\n",
			     show_algorithm_name(bank_alg));

			alg_weight = digest_algorithm_base_weight(bank_alg);
		}

		if (alg_weight > weight) {
			weight = alg_weight;
			preferred_alg = bank_alg;
		}
	}

	if (*hash_alg != TPM_ALG_AUTO)
		return false;

	if (preferred_alg == TPM_ALG_NULL)
		return false;

	*hash_alg = preferred_alg;

	info("%s PCR bank voted\n", show_algorithm_name(preferred_alg));

	return true;
}
