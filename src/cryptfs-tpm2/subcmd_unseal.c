/*
 * Unseal sub-command
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

static bool opt_unseal_passphrase;
static char *opt_output_file;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s unseal <object>\n", prog);
	info_cont("\nobject:\n");
	info_cont("  The object to be unsealed. The allowed values are:\n"
		  "    passphrase: Passphrase used to encrypt LUKS\n");
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

		rc = cryptfs_tpm2_unseal_passphrase(TPM_ALG_NULL, (void **)&passphrase,
						    &passphrase_size);
		if (rc)
			return rc;

		dbg_cont("Dumping the passphrase:\n");
		for (size_t i = 0; i < passphrase_size; i++)
			dbg_cont("0x%02x ", passphrase[i]);
		dbg_cont("\n");

		if (opt_output_file)
			rc = save_output_file(opt_output_file, passphrase,
					      passphrase_size);
	}

	return rc;
}

static struct option long_opts[] = {
	{ "output", required_argument, NULL, 'o' },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_unseal = {
	.name = "unseal",
	.optstring = "-o:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_unseal,
};