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

static bool opt_setup_key;
static bool opt_setup_passphrase;
static char *opt_passphrase;
static TPMI_ALG_HASH opt_pcr_bank_alg = TPM2_ALG_NULL;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s <options> seal <object> <args>\n", prog);
	info_cont("\nobject:\n");
	info_cont("  The object to be sealed. The allowed values are:\n"
		  "  - passphrase: Passphrase used to encrypt LUKS\n"
		  "  - key: Primary key used to seal the passphrase\n"
		  "  - all: All above\n");
	info_cont("\nargs:\n");
	info_cont("  --pcr-bank-alg, -P:\n"
		  "    (optional) Use the specified PCR bank to bind the\n"
		  "    created primary key and passphrase.\n");
	info_cont("  --passphrase, -p:\n"
		  "    (optional) Explicitly set the passphrase value\n"
		  "    (32-byte at most) instead of the one generated\n"
		  "    by TPM randomly. This parameter allows to be\n"
		  "    specified as a file path.\n");
	info_cont("  --no-da:\n"
		  "    (optional) The authorization failure never cause\n"
		  "    DA lockout\n");
}

#define EXTRA_OPT_BASE			0x8100
#define EXTRA_OPT_NO_DA			(EXTRA_OPT_BASE + 0)

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 'p':
		opt_passphrase = optarg;
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
	case EXTRA_OPT_NO_DA:
		option_no_da = true;
		break;
	case 1:
		if (!strcasecmp(optarg, "key"))
			opt_setup_key = 1;
		else if (!strcasecmp(optarg, "passphrase"))
			opt_setup_passphrase = 1;
		else if (!strcasecmp(optarg, "all")) {
			opt_setup_key = 1;
			opt_setup_passphrase = 1;
		} else {
			err("Unrecognized value\n");
			return -1;
		}
                break;
	default:
		return -1;
	}

	if (opt_passphrase && !opt_setup_passphrase) {
		warn("-p option is ignored if the object to be sealed is not "
		     "passphrase\n");
		opt_passphrase = NULL;
	}

	return 0;
}

static int
run_seal(char *prog)
{
	int rc = 0;

	if (opt_setup_key) {
		rc = cryptfs_tpm2_create_primary_key(opt_pcr_bank_alg);
		if (rc)
			return rc;
	}

	if (opt_setup_passphrase) {
		size_t size;

		if (opt_passphrase) {
			rc = cryptfs_tpm2_util_load_file(opt_passphrase,
							 (uint8_t **)&opt_passphrase,
							 (unsigned long *)&size);
			if (rc)
				size = strlen(opt_passphrase);
		} else
			size = 0;

		if (size > CRYPTFS_TPM2_PASSPHRASE_MAX_SIZE) {
			err("The passphrase explicitly specified is too long\n");
			return -1;
		}

		rc = cryptfs_tpm2_create_passphrase(opt_passphrase, size,
						    opt_pcr_bank_alg);
		if (rc)
			return rc;
	}

	return rc;
}

static struct option long_opts[] = {
	{ "passphrase", required_argument, NULL, 'p' },
	{ "pcr-bank-alg", required_argument, NULL, 'P' },
	{ "no-da", no_argument, NULL, EXTRA_OPT_NO_DA },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_seal = {
	.name = "seal",
	.optstring = "-p:P:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_seal,
};
