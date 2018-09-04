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

#ifndef O_LARGEFILE
  #define O_LARGEFILE		0
#endif

static int show_verbose;

int
util_digest_size(TPMI_ALG_HASH hash_alg, UINT16 *alg_size)
{
	switch (hash_alg) {
	case TPM2_ALG_SHA1:
		*alg_size = TPM2_SHA1_DIGEST_SIZE;
		break;
	case TPM2_ALG_SHA256:
		*alg_size = TPM2_SHA256_DIGEST_SIZE;
		break;
	case TPM2_ALG_SHA384:
		*alg_size = TPM2_SHA384_DIGEST_SIZE;
		break;
	case TPM2_ALG_SHA512:
		*alg_size = TPM2_SHA512_DIGEST_SIZE;
		break;
	case TPM2_ALG_SM3_256:
		*alg_size = TPM2_SM3_256_DIGEST_SIZE;
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
                                free(dir_name);
                                return -1;
                        }
                }
                free(dir_name);
        } while (dir != dir_delim);

        return 0;
}

bool
cryptfs_tpm2_util_file_exists(const char *file_path)
{
	struct stat statbuf;

	return !stat(file_path, &statbuf);
}

void
cryptfs_tpm2_util_hex_dump(const char *prompt, const uint8_t *data,
			   unsigned int data_size)
{
	if (prompt)
		dbg("%s (%d-byte): ", prompt, data_size);

	for (uint8_t i = 0; i < data_size; ++i)
		dbg_cont("%02x", data[i]);

	dbg_cont("\n");
}

int
cryptfs_tpm2_util_load_file(const char *file_path, uint8_t **out,
			    unsigned long *out_len)
{
	FILE *fp;
	uint8_t *buf;
	unsigned int size;
	int ret;

	dbg("Opening file %s ...\n", file_path);

	fp = fopen(file_path, "rb");
	if (!fp) {
		err("Failed to open file %s.\n", file_path);
		return -1;
	}

	if (fseek(fp, 0, SEEK_END)) {
		ret = -1;
		err("Failed to seek the end of file.\n");
		goto err;
	}

	size = ftell(fp);
	if (!size) {
		ret = -1;
		err("Empty file.\n");
		goto err;
	}

	rewind(fp);

	buf = (uint8_t *)malloc(size);
	if (!buf) {
		ret = -1;
		err("Failed to allocate memory for file.\n");
		goto err;
	}

	if (fread(buf, size, 1, fp) != 1) {
		ret = -1;
		err("Failed to read file.\n");
		free(buf);
	} else {
		*out = buf;
		*out_len = size;
		ret = 0;
	}

err:
	fclose(fp);

	return ret;
}

int
cryptfs_tpm2_util_save_output_file(const char *file_path, uint8_t *buf,
				   unsigned long size)
{
	FILE *fp;

	dbg("Saving output file %s ...\n", file_path);

	fp = fopen(file_path, "w");
	if (!fp) {
		err("Failed to create output file.\n");
		return -1;
	}

	if (fwrite(buf, size, 1, fp) != 1) {
		fclose(fp);
		err("Failed to write output file.\n");
		return -1;
	}

	fclose(fp);

	return 0;
}

int
get_input(const char *prompt, uint8_t *buf, unsigned int *buf_len)
{
	if (prompt) {
		info_cont("%s", prompt);
		fflush(stdout);
	}

	struct termios term;
	int rc;

	rc = tcgetattr(STDIN_FILENO, &term);
	if (rc)
		return rc;

	term.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);

	char input[256];

	memset(input, 0, sizeof(input));
	rc = scanf("%255[^\n]", input);

	term.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);

	if (rc != 1)
		return EXIT_FAILURE;

	char cr;

	/* Work around the attribute warn_unused_result */
	rc = scanf("%c", &cr);
	puts("\n");

	unsigned int size = strlen(input);

	if (size > *buf_len)
		size = *buf_len;
	else
		*buf_len = size;

	strcpy((char *)buf, input);

	return EXIT_SUCCESS;
}

int
cryptfs_tpm2_util_get_owner_auth(uint8_t *owner_auth,
				 unsigned int *owner_auth_size)
{
	if (!owner_auth || !owner_auth_size || !*owner_auth_size)
		return EXIT_FAILURE;

	bool required;

	if (cryptfs_tpm2_capability_owner_auth_required(&required) ==
	    EXIT_FAILURE)
		return EXIT_FAILURE;

	unsigned int opt_owner_auth_size = 0;

	if (cryptfs_tpm2_option_get_owner_auth(NULL, &opt_owner_auth_size))
		return EXIT_FAILURE;

	if (required == true) {
		err("Wrong owner authentication\n");

		if (cryptfs_tpm2_option_get_interactive(&required) ==
		    EXIT_FAILURE)
			return EXIT_FAILURE;

		if (required == false)
			return EXIT_FAILURE;

		if (get_input("Owner Authentication: ", owner_auth,
			      owner_auth_size) == EXIT_FAILURE)
			return EXIT_FAILURE;
	} else if (opt_owner_auth_size) {
		warn("Ignore --owner-auth due to owner authentication not "
		     "required\n");

		*owner_auth_size = 0;
	}

	return EXIT_SUCCESS;
}

int
cryptfs_tpm2_util_get_primary_key_secret(uint8_t *secret,
					 unsigned int *secret_size)
{
	bool required;

	if (cryptfs_tpm2_option_get_interactive(&required) ==
	    EXIT_FAILURE)
		return EXIT_FAILURE;

	if (required == false)
		return EXIT_FAILURE;

	if (!secret || !secret_size || !*secret_size)
		return EXIT_FAILURE;

	if (get_input("Primary Key Secret: ", secret,
		      secret_size) == EXIT_FAILURE)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int
cryptfs_tpm2_util_get_passphrase_secret(uint8_t *secret,
					unsigned int *secret_size)
{
	bool required;

	if (cryptfs_tpm2_option_get_interactive(&required))
		return EXIT_FAILURE;

	if (required == false)
		return EXIT_FAILURE;

	if (!secret || !secret_size || !*secret_size)
		return EXIT_FAILURE;

	if (get_input("Passphrase Secret: ", secret,
		      secret_size) == EXIT_FAILURE)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
