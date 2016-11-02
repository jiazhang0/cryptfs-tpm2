/*
 * Sub-command support
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

#define MAX_SUBCOMMANDS			16

static subcommand_t *curr_subcommand;
static unsigned int nr_subcommand;
static subcommand_t *subcommands[MAX_SUBCOMMANDS];
static char *prog_name;

int
subcommand_add(subcommand_t *subcmd)
{
	if (!subcmd->name || !subcmd->optstring || !subcmd->long_opts
			|| !subcmd->parse_arg)
		return -1;

	if (nr_subcommand >= MAX_SUBCOMMANDS)
		return -1;

	subcommands[nr_subcommand++] = subcmd;

	return 0;
}

subcommand_t *
subcommand_find(char *subcmd)
{
	unsigned int i;

	for (i = 0; i < nr_subcommand; ++i) {
		if (!eee_strcmp(subcmd, subcommands[i]->name))
			break;
	}
	if (i == nr_subcommand)
		return NULL;

	return subcommands[i];
}

int
subcommand_parse(char *prog, char *subcmd, int argc, char *argv[])
{
	subcommand_t *cmd;
	int subcmd_arg_parsed;

	dbg("Input subcommand: %s\n", subcmd);

	cmd = subcommand_find(subcmd);
	if (!cmd) {
		err("Unrecognized subcommand: %s\n", subcmd);
		return -1;
	}

	subcmd_arg_parsed = 0;

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, cmd->optstring,
				  cmd->long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case '?':
			err("Unrecongnized argument\n");
			return -1;
		default:	/* Command arguments */
			subcmd_arg_parsed = 1;
			if (cmd->parse_arg(opt, optarg)) {
				if (eee_strcmp(subcmd, "help"))
					cmd->show_usage(prog);
				return -1;
			}
		}
	}

	if (!subcmd_arg_parsed) {
		err("Nothing specified\n");
		if (eee_strcmp(cmd->name, "help"))
			err(". Run \"%s help %s \" for the help info\n",
			    prog, subcmd);
		else
			err_cont("\n");
		return -1;
	}

	curr_subcommand = cmd;
	if (!curr_subcommand) {
		err(". Run \"%s help %s \" for the help info\n",
		    prog, subcmd);
		return -1;
	}

	prog_name = prog;

	return 0;
}

int
subcommand_run_current(void)
{
	if (!curr_subcommand)
		return -1;

	return curr_subcommand->run(prog_name);
}