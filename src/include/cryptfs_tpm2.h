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

#ifndef CRYPTFS_TPM2_H
#define CRYPTFS_TPM2_H

#include <eee.h>
#include <subcommand.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

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

/* The PCR index used to seal/unseal the passphrase */
#define CRYPTFS_TPM2_PCR_INDEX			7

/* The maximum length of passphrase explicitly specified */
#define CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE	32

/* The persiste handle value for the primary key */
#define CRYPTFS_TPM2_PRIMARY_KEY_HANDLE		0x817FFFFF

/* The persiste handle value for the passphrase */
#define CRYPTFS_TPM2_PASSPHRASE_HANDLE		0x817FFFFE

extern const char *cryptfs_tpm2_git_commit;
extern const char *cryptfs_tpm2_build_machine;

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
cryptefs_tpm2_get_random(void *random, UINT16 req_size);

extern int
cryptfs_tpm2_create_primary_key(TPMI_ALG_HASH pcr_bank_alg,
				char *auth_password,
				unsigned int auth_password_size);

extern int
cryptfs_tpm2_create_passphrase(char *passphrase, size_t passphrase_size,
                               TPMI_ALG_HASH pcr_bank_alg,
			       char *auth_password,
			       unsigned int auth_password_size);

extern int
cryptfs_tpm2_unseal_passphrase(TPMI_ALG_HASH pcr_bank_alg, void **passphrase,
			       size_t *passphrase_size);

extern int
cryptfs_tpm2_evict_primary_key(char *auth_password,
			       unsigned int auth_password_size);

extern int
cryptfs_tpm2_evict_passphrase(char *auth_password,
			      unsigned int auth_password_size);

extern int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle, char *auth_password,
				 unsigned int auth_password_size);

extern int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle, char *auth_password,
				unsigned int auth_password_size);

#endif	/* CRYPTFS_TPM2_H */
