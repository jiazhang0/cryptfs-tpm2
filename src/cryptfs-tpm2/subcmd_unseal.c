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

static bool opt_unseal_passphrase;
static char *opt_output_file;
static TPMI_ALG_HASH opt_pcr_bank_alg = TPM2_ALG_NULL;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s <options> unseal <object>\n", prog);
	info_cont("\nobject:\n");
	info_cont("  The object to be unsealed. The allowed values are:\n"
		  "  - passphrase: Passphrase used to encrypt LUKS\n");
	info_cont("\nargs:\n");
	info_cont("  --pcr-bank-alg, -P:\n"
		  "    (optional) Use the specified PCR bank to bind the\n"
		  "    created primary key and passphrase.\n");
	info_cont("  --lockoutauth, -l:\n"
		  "    (optional) Specify the authorization value for\n"
		  "    lockout.\n");
}

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 1:
		if (!strcasecmp(optarg, "passphrase"))
			opt_unseal_passphrase = 1;
		else {
			err("Unrecognized value\n");
			return -1;
		}
                break;
	case 'o':
		opt_output_file = optarg;
		break;
	case 'P':
		if (!strcasecmp(optarg, "sha1"))
			opt_pcr_bank_alg = TPM2_ALG_SHA1;
		else if (!strcasecmp(optarg, "sha256"))
			opt_pcr_bank_alg = TPM2_ALG_SHA256;
		else if (!strcasecmp(optarg, "sha384"))
			opt_pcr_bank_alg = TPM2_ALG_SHA384;
		else if (!strcasecmp(optarg, "sha512"))
			opt_pcr_bank_alg = TPM2_ALG_SHA512;
		else if (!strcasecmp(optarg, "sm3_256"))
			opt_pcr_bank_alg = TPM2_ALG_SM3_256;
		else if (!strcasecmp(optarg, "auto"))
			opt_pcr_bank_alg = TPM2_ALG_AUTO;
		else {
			err("Unrecognized PCR bank algorithm\n");
			return -1;
		}

		if (cryptfs_tpm2_capability_pcr_bank_supported(&opt_pcr_bank_alg) == false) {
			err("Unsupported PCR bank algorithm\n");
			return -1;
		}

		break;
	default:
		return -1;
	}

	return 0;
}

static int
run_unseal(char *prog)
{
	int rc = 0;

	if (opt_unseal_passphrase) {
		unsigned char *passphrase;
		size_t passphrase_size;

		rc = cryptfs_tpm2_unseal_passphrase(opt_pcr_bank_alg,
						    (void **)&passphrase,
						    &passphrase_size);
		if (rc)
			return rc;

		if (!opt_output_file) {
			info("Dumping the passphrase (%Zd-byte):\n",
			     passphrase_size);

			for (size_t i = 0; i < passphrase_size; i++)
				info_cont("0x%02x ", passphrase[i]);
			info_cont("\n");
		} else
			rc = cryptfs_tpm2_util_save_output_file(opt_output_file,
								passphrase,
								passphrase_size);
	}

	return rc;
}

static struct option long_opts[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "pcr-bank-alg", required_argument, NULL, 'P' },
	{ "lockoutauth", optional_argument, NULL, 'l' },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_unseal = {
	.name = "unseal",
	.optstring = "-o:P:l:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_unseal,
};
