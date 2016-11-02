/*
 * Help sub-command
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

static char *opt_command;

static void
show_usage(char *prog)
{
	info_cont("\nNobody can help you this time :(\n");
}

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 1:
		{
			subcommand_t *cmd;

			cmd = subcommand_find(optarg);
			if (!cmd) {
				err("Unrecognized command argument "
				    "\"%s\" specified\n", optarg);
				return -1;
			}
			opt_command = optarg;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

static int
run_help(char *prog)
{
	subcommand_find(opt_command)->show_usage(prog);

	return 0;
}

static struct option long_opts[] = {
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_help = {
	.name = "help",
	.optstring = "-",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_help,
};