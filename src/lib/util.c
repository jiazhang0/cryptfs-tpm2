/*
 * Utility routines
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

static int show_verbose;

int
util_digest_size(TPMI_ALG_HASH hash_alg, UINT16 *alg_size)
{
	switch (hash_alg) {
	case TPM_ALG_SHA1:
		*alg_size = SHA1_DIGEST_SIZE;
		break;
	case TPM_ALG_SHA256:
		*alg_size = SHA256_DIGEST_SIZE;
		break;
	case TPM_ALG_SHA384:
		*alg_size = SHA384_DIGEST_SIZE;
		break;
	case TPM_ALG_SHA512:
		*alg_size = SHA512_DIGEST_SIZE;
		break;
	case TPM_ALG_SM3_256:
		*alg_size = SM3_256_DIGEST_SIZE;
		break;
	default:
		err("Unsupported hash algorithm %#x\n", hash_alg);
		return -1;
	}

	return 0;
}

int
cryptfs_tpm2_util_verbose(void)
{
	return show_verbose;
}

void
cryptfs_tpm2_util_set_verbosity(int verbose)
{
	show_verbose = verbose;
}

char **
cryptfs_tpm2_util_split_string(char *in, char *delim, unsigned int *nr)
{
	char **out = NULL;
	unsigned int delim_sz = strlen(delim);

	*nr = 0;
	while (*in) {
		char *p = strstr(in, delim);
		int len;

		if (p)
			len = p - in;
		else
			len = strlen(in);

		char *str = strndup(in, len + 1);
		if (!str) {
			free(out);
			return NULL;
		}

		out = realloc(out, sizeof(char *) * (*nr + 1));
		if (!out) {
			free(str);
			return NULL;
		}

		str[len] = 0;
		out[(*nr)++] = str;

		in += len;
		if (p)
			in += delim_sz;
	}

	return out;
}

int
cryptfs_tpm2_util_mkdir(const char *dir, mode_t mode)
{
	const char *dir_delim = dir;
	const char *dir_start = dir;
	char *dir_name;

	do {
		dir = dir_delim + strspn(dir_delim, "/");
                dir_delim = dir + strcspn(dir, "/");
                dir_name = strndup(dir_start, dir - dir_start);
                if (*dir_name) {
                        if (mkdir(dir_name, mode) && errno != EEXIST) {
                                err("Unable to create directory %s", dir_name);
                                eee_mfree(dir_name);
                                return -1;
                        }
                }
                eee_mfree(dir_name);
        } while (dir != dir_delim);

        return 0;
}

bool
cryptfs_tpm2_util_file_exists(const char *file_path)
{
	struct stat statbuf;

	return !stat(file_path, &statbuf);
}
