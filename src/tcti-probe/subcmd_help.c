/*
 * BSD 2-clause "Simplified" License
 *
 * Copyright (c) 2016-2017, Lans Zhang <jia.zhang@windriver.com>, Wind River Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:
 * 	Lans Zhang <jia.zhang@windriver.com>
 */

#include <cryptfs_tpm2.h>

static char *opt_command;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s help <subcommand>\n", prog);
	info_cont("\nsubcommand:\n");
	info_cont("  The subcommand to be shown.\n");
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
				err("Unrecognized subcommand argument "
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
	if (!opt_command) {
		show_usage(prog);
		return -1;
	}

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