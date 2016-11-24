/*
 * Cryptfs-TPM2 core
 *
 * Copyright (c) 2016, Wind River Systems, Inc.
 * All rights reserved.
 *
 * See "LICENSE" for license terms.
 *
 * Author:
 *	  Lans Zhang <jia.zhang@windriver.com>
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

extern int
cryptefs_tpm2_get_random(void *random, UINT16 req_size);

extern int
cryptfs_tpm2_create_primary_key(int pcr_bound, char *auth_password);

extern int
cryptfs_tpm2_create_passphrase(char *passphrase, size_t passphrase_size,
			       int pcr_bound, char *auth_password);

extern int
cryptfs_tpm2_unseal_passphrase(void **passphrase, size_t *passphrase_size);

extern int
cryptfs_tpm2_evict_primary_key(char *auth_password);

extern int
cryptfs_tpm2_evict_passphrase(char *auth_password);

extern int
cryptfs_tpm2_persist_primary_key(TPMI_DH_OBJECT handle, char *auth_password);

extern int
cryptfs_tpm2_persist_passphrase(TPMI_DH_OBJECT handle, char *auth_password);

#endif	/* CRYPTFS_TPM2_H */
