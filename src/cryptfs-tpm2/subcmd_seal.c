/*
 * Seal sub-command
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

static char *opt_auth_password;
static bool opt_setup_key;
static bool opt_setup_passphrase;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s seal <object> <args>\n", prog);
	info_cont("\nobject:\n");
	info_cont("  The object to be sealed. The allowed values are:\n"
		  "    passphrase: Passphrase used to encrypt LUKS\n"
		  "    key: Primary key used to seal the passphrase\n"
		  "    all: All above\n");
	info_cont("\nargs:\n");
	info_cont("  --auth, -a: (optional) Set the authorization value for "
		  "owner hierarchy.\n");
}

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 'a':
		if (strlen(optarg) > sizeof(TPMU_HA)) {
			err("The authorization value for owner hierarchy is "
			    "no more than %d characters\n",
			    (int)sizeof(TPMU_HA));
			return -1;
		}
		opt_auth_password = optarg;
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

	return 0;
}

static int
run_seal(char *prog)
{
	int rc = 0;

	if (opt_setup_key) {
		rc = cryptfs_tpm2_create_primary_key(opt_auth_password);
		if (rc)
			return rc;
	}

	if (opt_setup_passphrase) {
		rc = cryptfs_tpm2_create_passphrase(opt_auth_password);
		if (rc)
			return rc;
	}

	return rc;
}

static struct option long_opts[] = {
	{ "auth", required_argument, NULL, 'a' },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_seal = {
	.name = "seal",
	.optstring = "-a:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_seal,
};