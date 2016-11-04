/*
 * Cryptfs-TPM2 main program
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

static int opt_quite;

static void
show_banner(void)
{
	info_cont("\nCryptfs-TPM 2.0 tool\n");
	info_cont("(C)Copyright 2016, Wind River Systems, Inc.\n");
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
	info_cont("  seal: Create the persistent primary key and seal the "
		  "passphrase\n");
	info_cont("  unseal: Unseal the passphrase\n");
	info_cont("  evict: Evict the persistent primary key and passphrase\n");
	info_cont("\nargs:\n");
	info_cont("  Run `%s help <subcommand>` for the details\n", prog);
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
extern subcommand_t subcommand_evict;
extern subcommand_t subcommand_seal;
extern subcommand_t subcommand_unseal;

static void
exit_notify(void)
{
	if (cryptfs_tpm2_util_verbose())
		info("cryptfs-tpm2 exiting with %d (%s)\n", errno, strerror(errno));
}

int
main(int argc, char *argv[], char *envp[])
{
	atexit(exit_notify);

	subcommand_add(&subcommand_help);
	subcommand_add(&subcommand_evict);
	subcommand_add(&subcommand_seal);
	subcommand_add(&subcommand_unseal);

	int rc = parse_options(argc, argv);
	if (rc)
		return rc;

	if (!opt_quite)
		show_banner();

	return subcommand_run_current();
}