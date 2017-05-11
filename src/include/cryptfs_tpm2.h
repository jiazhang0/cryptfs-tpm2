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

#include <tcti/tcti_socket.h>
#include <tcti/tcti_device.h>
#include <tcti/tcti-tabrmd.h>

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

#define TPM_ALG_AUTO		0x4000

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
