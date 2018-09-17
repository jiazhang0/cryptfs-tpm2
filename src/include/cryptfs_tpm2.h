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

#ifndef CRYPTFS_TPM2_H
#define CRYPTFS_TPM2_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <termios.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/limits.h>

#include <subcommand.h>

#ifndef TSS2_LEGACY_V1
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2-tcti-tabrmd.h>
#else
#include <tcti/tcti_socket.h>
#include <tcti/tcti_device.h>
#include <tcti/tcti-tabrmd.h>
#endif

#define stringify(x)			#x

#ifndef offsetof
  #define offsetof(type, member)	((unsigned long)&((type *)0)->member)
#endif

#define container_of(ptr, type, member)	({	\
	const __typeof__(((type *)0)->member) *__ptr = (ptr);	\
	(type *)((char *)__ptr - offsetof(type, member));})

#define align_up(x, n)	(((x) + ((n) - 1)) & ~((n) - 1))
#define aligned(x, n)	(!!((x) & ((n) - 1)))

#define cryptfs_tpm2_assert(condition, fmt, ...)	\
	do {	\
		if (!(condition)) {	\
			err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno)); \
			exit(EXIT_FAILURE);	\
		}	\
	} while (0)

/* Definitions to make it compatible with tpm2-tss 1.x */
#ifdef TSS2_LEGACY_V1
#define TPM2_RC                                 TPM_RC
#define TPM2_RC_SUCCESS                         TPM_RC_SUCCESS
#define TPM2_RC_LOCKOUT                         TPM_RC_LOCKOUT
#define TPM2_RC_FMT1                            RC_FMT1
#define TPM2_RC_BAD_AUTH                        TPM_RC_BAD_AUTH
#define TPM2_RC_AUTH_FAIL                       TPM_RC_AUTH_FAIL

#define TPM2_ALG_RSA                            TPM_ALG_RSA
#define TPM2_ALG_HMAC                           TPM_ALG_HMAC
#define TPM2_ALG_AES                            TPM_ALG_AES
#define TPM2_ALG_KEYEDHASH                      TPM_ALG_KEYEDHASH
#define TPM2_ALG_MGF1                           TPM_ALG_MGF1
#define TPM2_ALG_XOR                            TPM_ALG_XOR
#define TPM2_ALG_NULL                           TPM_ALG_NULL
#define TPM2_ALG_SHA1                           TPM_ALG_SHA1
#define TPM2_ALG_SHA256                         TPM_ALG_SHA256
#define TPM2_ALG_SHA384                         TPM_ALG_SHA384
#define TPM2_ALG_SHA512                         TPM_ALG_SHA512
#define TPM2_ALG_SM3_256                        TPM_ALG_SM3_256
#define TPM2_ALG_SM4                            TPM_ALG_SM4
#define TPM2_ALG_RSASSA                         TPM_ALG_RSASSA
#define TPM2_ALG_RSAES                          TPM_ALG_RSAES
#define TPM2_ALG_RSAPSS                         TPM_ALG_RSAPSS
#define TPM2_ALG_OAEP                           TPM_ALG_OAEP
#define TPM2_ALG_ECDSA                          TPM_ALG_ECDSA
#define TPM2_ALG_ECDH                           TPM_ALG_ECDH
#define TPM2_ALG_SM2                            TPM_ALG_SM2
#define TPM2_ALG_ECSCHNORR                      TPM_ALG_ECSCHNORR
#define TPM2_ALG_KDF1_SP800_56A                 TPM_ALG_KDF1_SP800_56A
#define TPM2_ALG_KDF1_SP800_108                 TPM_ALG_KDF1_SP800_108
#define TPM2_ALG_ECC                            TPM_ALG_ECC
#define TPM2_ALG_SYMCIPHER                      TPM_ALG_SYMCIPHER
#define TPM2_ALG_CTR                            TPM_ALG_CTR
#define TPM2_ALG_OFB                            TPM_ALG_OFB
#define TPM2_ALG_CBC                            TPM_ALG_CBC
#define TPM2_ALG_CFB                            TPM_ALG_CFB
#define TPM2_ALG_ECB                            TPM_ALG_ECB
#define TPM2_ALG_ERROR                          TPM_ALG_ERROR
#define TPM2_ALG_ID                             TPM_ALG_ID

#define TPM2_SHA1_DIGEST_SIZE                   SHA1_DIGEST_SIZE
#define TPM2_SHA256_DIGEST_SIZE                 SHA256_DIGEST_SIZE
#define TPM2_SHA384_DIGEST_SIZE                 SHA384_DIGEST_SIZE
#define TPM2_SHA512_DIGEST_SIZE                 SHA512_DIGEST_SIZE
#define TPM2_SM3_256_DIGEST_SIZE                SM3_256_DIGEST_SIZE

#define TPM2_ECC_NIST_P256                      TPM_ECC_NIST_P256

#define TPM2_PCR_SELECT_MAX                     PCR_SELECT_MAX

#define TPM2_CAP_HANDLES                        TPM_CAP_HANDLES
#define TPM2_CAP_ALGS                           TPM_CAP_ALGS
#define TPM2_CAP_ALGS                           TPM_CAP_ALGS
#define TPM2_CAP_PCRS                           TPM_CAP_PCRS
#define TPM2_CAP_TPM_PROPERTIES                 TPM_CAP_TPM_PROPERTIES

#define TPM2_PT                                 TPM_PT
#define TPM2_PT_NONE                            TPM_PT_NONE
#define TPM2_PT_TPM2_HR_PERSISTENT              TPM_PT_HR_PERSISTENT
#define TPM2_PT_LOCKOUT_INTERVAL                TPM_PT_LOCKOUT_INTERVAL
#define TPM2_PT_LOCKOUT_COUNTER                 TPM_PT_LOCKOUT_COUNTER
#define TPM2_PT_MAX_AUTH_FAIL                   TPM_PT_MAX_AUTH_FAIL
#define TPM2_PT_LOCKOUT_RECOVERY                TPM_PT_LOCKOUT_RECOVERY
#define TPM2_PT_PERMANENT                       TPM_PT_PERMANENT

#define TPM2_SE                                 TPM_SE
#define TPM2_SE_TRIAL                           TPM_SE_TRIAL
#define TPM2_SE_POLICY                          TPM_SE_POLICY

#define TPM2_HT_PERSISTENT                      TPM_HT_PERSISTENT

#define TPM2_RH_OWNER                           TPM_RH_OWNER
#define TPM2_RH_LOCKOUT                         TPM_RH_LOCKOUT
#define TPM2_RH_NULL                            TPM_RH_NULL

#define TPM2_RS_PW                              TPM_RS_PW

#define TPM2_HANDLE                             TPM_HANDLE

#define TSS2_RC_LAYER_MASK                      TSS2_ERROR_LEVEL_MASK
#endif

/* The PCR index used to seal/unseal the passphrase */
#define CRYPTFS_TPM2_PCR_INDEX			7

/* The maximum length of passphrase explicitly specified */
#define CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE	64

/* The maximum length of secret for hierarchy authentication */
#define CRYPTFS_TPM2_SECRET_MAX_SIZE		256

/* The persiste handle value for the primary key */
#define CRYPTFS_TPM2_PRIMARY_KEY_HANDLE		0x817FFFFF

/* The persiste handle value for the passphrase */
#define CRYPTFS_TPM2_PASSPHRASE_HANDLE		0x817FFFFE

/* The maximum atempts of prompting to type the lockout auth */
#define CRYPTFS_TPM2_MAX_LOCKOUT_RETRY		3

#define gettid()		syscall(__NR_gettid)

#define __pr__(level, io, fmt, ...)	\
	do {	\
		time_t __t__ = time(NULL);	\
		struct tm __loc__;	\
		localtime_r(&__t__, &__loc__);	\
		char __buf__[64]; \
		strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);	\
		fprintf(io, "%s: [" #level "] " fmt, __buf__, ##__VA_ARGS__);	\
	} while (0)

#define die(fmt, ...)	\
	do {	\
		__pr__(FAULT, stderr, fmt, ##__VA_ARGS__);	\
		exit(EXIT_FAILURE);	\
	} while (0)

#ifdef DEBUG
  #define dbg(fmt, ...)	\
	do {	\
		__pr__(DEBUG, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

  #define dbg_cont(fmt, ...)	\
	do {	\
		fprintf(stdout, fmt, ##__VA_ARGS__);	\
	} while (0)
#else
  #define dbg(fmt, ...)
  #define dbg_cont(fmt, ...)
#endif

#define info(fmt, ...)	\
	do {	\
		__pr__(INFO, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

#define info_cont(fmt, ...)	\
	fprintf(stdout, fmt, ##__VA_ARGS__)

#define warn(fmt, ...)	\
	do {	\
		__pr__(WARNING, stdout, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err(fmt, ...)	\
	do {	\
		__pr__(ERROR, stderr, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err_cont(fmt, ...)	\
	fprintf(stderr, fmt, ##__VA_ARGS__)

extern const char *cryptfs_tpm2_git_commit;
extern const char *cryptfs_tpm2_build_machine;
extern int option_quite;
extern bool option_no_da;

#define TPM2_ALG_AUTO		0x4000

extern int
cryptfs_tpm2_util_verbose(void);

extern void
cryptfs_tpm2_util_set_verbosity(int verbose);

extern char **
cryptfs_tpm2_util_split_string(char *in, char *delim, unsigned int *nr);

extern int
cryptfs_tpm2_util_mkdir(const char *dir, mode_t mode);

extern bool
cryptfs_tpm2_util_file_exists(const char *file_path);

extern void
cryptfs_tpm2_util_hex_dump(const char *prompt, const uint8_t *data,
			   unsigned int data_size);

extern int
cryptfs_tpm2_util_load_file(const char *file_path, uint8_t **out,
			    unsigned long *out_len);

extern int
cryptfs_tpm2_util_save_output_file(const char *file_path, uint8_t *buf,
				   unsigned long size);

extern int
cryptfs_tpm2_util_get_owner_auth(uint8_t *owner_auth,
				 unsigned int *owner_auth_size);

extern int
cryptfs_tpm2_util_get_primary_key_secret(uint8_t *secret,
					 unsigned int *secret_size);

extern int
cryptfs_tpm2_util_get_passphrase_secret(uint8_t *secret,
					unsigned int *secret_size);

extern TSS2_TCTI_CONTEXT *
cryptfs_tpm2_tcti_init_context(void);

extern void
cryptfs_tpm2_tcti_teardown_context(TSS2_TCTI_CONTEXT *ctx);

extern int
cryptfs_tpm2_option_set_owner_auth(uint8_t *buf, unsigned int *buf_size);

extern int
cryptfs_tpm2_option_get_owner_auth(uint8_t *buf, unsigned int *buf_size);

extern int
cryptfs_tpm2_option_set_lockout_auth(uint8_t *buf, unsigned int *buf_size);

extern int
cryptfs_tpm2_option_get_lockout_auth(uint8_t *buf, unsigned int *buf_size);

extern int
cryptfs_tpm2_option_set_primary_key_secret(uint8_t *buf,
					   unsigned int *buf_size);

extern int
cryptfs_tpm2_option_get_primary_key_secret(uint8_t *buf,
					   unsigned int *buf_size);

extern int
cryptfs_tpm2_option_set_passphrase_secret(uint8_t *buf,
					  unsigned int *buf_size);

extern int
cryptfs_tpm2_option_get_passphrase_secret(uint8_t *buf,
					  unsigned int *buf_size);

extern void
cryptfs_tpm2_option_set_interactive(void);

extern int
cryptfs_tpm2_option_get_interactive(bool *required);

extern int
cryptefs_tpm2_get_random(uint8_t *random, size_t *req_size);

extern int
cryptfs_tpm2_create_primary_key(TPMI_ALG_HASH pcr_bank_alg);

extern int
cryptfs_tpm2_create_passphrase(char *passphrase, size_t passphrase_size,
                               TPMI_ALG_HASH pcr_bank_alg);

extern int
cryptfs_tpm2_unseal_passphrase(TPMI_ALG_HASH pcr_bank_alg, void **passphrase,
			       size_t *passphrase_size);

extern int
cryptfs_tpm2_evict_primary_key(void);

extern int
cryptfs_tpm2_evict_passphrase(void);

extern int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle);

extern int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle);

extern bool
cryptfs_tpm2_capability_digest_supported(TPMI_ALG_HASH *hash_alg);

bool
cryptfs_tpm2_capability_pcr_bank_supported(TPMI_ALG_HASH *hash_alg);

int
cryptfs_tpm2_capability_in_lockout(bool *in_lockout);

int
cryptfs_tpm2_capability_lockout_auth_required(bool *required);

int
cryptfs_tpm2_capability_owner_auth_required(bool *required);

extern int
cryptfs_tpm2_capability_da_disabled(bool *disabled);

extern int
cryptfs_tpm2_capability_lockout_enforced(bool *enforced);

extern int
cryptfs_tpm2_capability_get_lockout_counter(UINT32 *counter);

extern int
cryptfs_tpm2_capability_get_max_tries(UINT32 *max_tries);

extern int
cryptfs_tpm2_capability_get_lockout_recovery(UINT32 *recovery);

int
cryptfs_tpm2_read_pcr(TPMI_ALG_HASH bank_alg, unsigned int index,
		      BYTE *out);

#endif	/* CRYPTFS_TPM2_H */
