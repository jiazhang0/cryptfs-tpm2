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
		if (!strcmp(subcmd, subcommands[i]->name))
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

	dbg("Input subcommand: %s\n", subcmd);

	cmd = subcommand_find(subcmd);
	if (!cmd) {
		err("Unrecognized subcommand: %s\n", subcmd);
		return -1;
	}

	optind = 1;
	opterr = 0;

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, cmd->optstring,
				  cmd->long_opts, NULL);
		if (opt == -1)
			break;

		dbg("opt 0x%x, optind %d, argc %d, argv[i] %s, optarg %s\n",
		    opt, optind, argc, argv[optind - 1], optarg);

		switch (opt) {
		default:
			if (cmd->parse_arg(opt, optarg))
				return -1;
			break;
		case '?':
		case ':':
			cmd->show_usage(prog);
			return -1;
		}
	}

	curr_subcommand = cmd;
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
