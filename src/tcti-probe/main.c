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

static int opt_quite;

static void
show_banner(void)
{
	info_cont("\ntcti utility\n");
	info_cont("(C)Copyright 2017, Wind River Systems, Inc.\n");
	info_cont("Version: %s+git-%s\n", VERSION, cryptfs_tpm2_git_commit);
	info_cont("Build Machine: %s\n", cryptfs_tpm2_build_machine);
	info_cont("Build Time: " __DATE__ " " __TIME__ "\n\n");
}

static void
show_version(void)
{
	info_cont("%s\n", VERSION);
}

static void
show_usage(const char *prog)
{
	info_cont("usage: %s <options> <subcommand> [<args>]\n",
		  prog);
	info_cont("\noptions:\n");
	info_cont("  --help, -h: Print this help information\n");
	info_cont("  --version, -V: Show version number\n");
	info_cont("  --verbose, -v: Show verbose messages\n");
	info_cont("  --quite, -q: Don't show banner information\n");
	info_cont("\nsubcommand:\n");
	info_cont("  help: Display the help information for the "
		  "specified command\n");
	info_cont("  wait: wait for the resource manager getting ready\n");
}

static int
parse_options(int argc, char *argv[])
{
	char opts[] = "-hVvq";
	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "quite", no_argument, NULL, 'q' },
		{ 0 },	/* NULL terminated */
	};

	while (1) {
		int opt, index;

		opt = getopt_long(argc, argv, opts, long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case '?':
			err("Unrecognized option\n");
			return -1;
		case 'h':
			show_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
		case 'v':
			cryptfs_tpm2_util_set_verbosity(1);
			break;
		case 'q':
			opt_quite = 1;
			break;
		case 1:
			index = optind;
			optind = 1;
			if (subcommand_parse(argv[0], optarg, argc - index + 1,
					     argv + index - 1)) 
				exit(EXIT_FAILURE);
			return 0;
		default:
			show_usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

extern subcommand_t subcommand_help;
extern subcommand_t subcommand_wait;

static void
exit_notify(void)
{
	if (cryptfs_tpm2_util_verbose())
		info("tcti-probe exiting with %d (%s)\n", errno,
		     strerror(errno));
}

int
main(int argc, char *argv[], char *envp[])
{
	atexit(exit_notify);

	subcommand_add(&subcommand_help);
	subcommand_add(&subcommand_wait);

	int rc = parse_options(argc, argv);
	if (rc)
		return rc;

	if (!opt_quite)
		show_banner();

	return subcommand_run_current();
}
