/*
 * Evict sub-command
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
static bool opt_evict_key;
static bool opt_evict_passphrase;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s evict <object> <args>\n", prog);
	info_cont("\nobject:\n");
	info_cont("  The object to be evicted. The allowed values are:\n"
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
		if (strlen(optarg) >= sizeof(TPMU_HA)) {
			err("The authorization value for owner hierarchy is "
			    "no more than %d characters\n",
			    (int)sizeof(TPMU_HA) - 1);
			return -1;
		}
		opt_auth_password = optarg;
                break;
	case 1:
		if (!strcasecmp(optarg, "key"))
			opt_evict_key = 1;
		else if (!strcasecmp(optarg, "passphrase"))
			opt_evict_passphrase = 1;
		else if (!strcasecmp(optarg, "all")) {
			opt_evict_key = 1;
			opt_evict_passphrase = 1;
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
run_evict(char *prog)
{
	int rc = 0;

	if (opt_evict_passphrase) {
		rc = cryptfs_tpm2_evict_primary_key(opt_auth_password,
						    opt_auth_password ?
						    strlen(opt_auth_password) :
						    0);
		if (!rc)
			info("The persistent passphrase is evicted\n");
	}

	if (opt_evict_key) {
		int rc1 = cryptfs_tpm2_evict_passphrase(opt_auth_password,
							opt_auth_password ?
							strlen(opt_auth_password) :
							0);
		if (!rc1)
			info("The persistent primary key is evicted\n");
		else
			rc |= rc1;
	}

	return rc;
}

static struct option long_opts[] = {
	{ "auth", required_argument, NULL, 'a' },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_evict = {
	.name = "evict",
	.optstring = "-a:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_evict,
};