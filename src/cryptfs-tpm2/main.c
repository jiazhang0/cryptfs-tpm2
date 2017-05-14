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
 *        Lans Zhang <jia.zhang@windriver.com>
 */

#include <cryptfs_tpm2.h>

static void
show_banner(void)
{
	info_cont("\nCryptfs-TPM 2.0 tool\n");
	info_cont("(C)Copyright 2016-2017, Wind River Systems, Inc.\n");
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
	info_cont("  --help, -h:\n"
		  "    Print this help information\n");
	info_cont("  --version, -V:\n"
		  "    Show version number\n");
	info_cont("  --verbose, -v:\n"
		  "    Show verbose messages\n");
	info_cont("  --quite, -q:\n"
		  "    Don't show banner information\n");
	info_cont("  --owner-auth:\n"
		  "    Specify the authorization value for owner "
		  "hierarchy\n");
	info_cont("  --lockout-auth:\n"
		  "    Specify the authorization value for lockout\n");
	info_cont("  --key-secret:\n"
		  "    The authorization secret used to access "
		  "the primary key object\n");
	info_cont("  --passphrase-secret:\n"
		  "    The authorization secret used to access "
		  "the passphrase object\n");
	info_cont("  --interactive:\n"
		  "    Prompt the user to type owner authentication, "
		  "the secret info of the primary key or passphrase.\n"
		  "    Default: FALSE\n");
	info_cont("\nsubcommand:\n");
	info_cont("  help:\n"
		  "    Display the help information for the "
		  "specified command\n");
	info_cont("  seal:\n"
		  "    Create the persistent primary key and seal the "
		  "passphrase\n");
	info_cont("  unseal:\n"
		  "    Unseal the passphrase\n");
	info_cont("  evict:\n"
		  "    Evict the persistent primary key and passphrase\n");
	info_cont("\nargs:\n");
	info_cont("  Run `%s help <subcommand>` for the details\n", prog);
}

#define EXTRA_OPT_BASE				0x8000
#define EXTRA_OPT_OWNER_AUTH			(EXTRA_OPT_BASE + 0)
#define EXTRA_OPT_LOCKOUT_AUTH			(EXTRA_OPT_BASE + 1)
#define EXTRA_OPT_KEY_SECRET_AUTH		(EXTRA_OPT_BASE + 2)
#define EXTRA_OPT_PASSPHRASE_SECRET_AUTH	(EXTRA_OPT_BASE + 3)
#define EXTRA_OPT_INTERACTIVE			(EXTRA_OPT_BASE + 4)

static int
parse_options(int argc, char *argv[])
{
	char opts[] = "-hVvq";
	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "quite", no_argument, NULL, 'q' },
		{ "owner-auth", required_argument, NULL,
		  EXTRA_OPT_OWNER_AUTH },
		{ "lockout-auth", required_argument, NULL,
		  EXTRA_OPT_LOCKOUT_AUTH },
		{ "key-secret", required_argument, NULL,
		  EXTRA_OPT_KEY_SECRET_AUTH },
		{ "passphrase-secret", required_argument, NULL,
		  EXTRA_OPT_PASSPHRASE_SECRET_AUTH },
		{ "interactive", no_argument, NULL,
		  EXTRA_OPT_INTERACTIVE },
		{ 0 },	/* NULL terminated */
	};

	while (1) {
		int opt, index;

		opt = getopt_long(argc, argv, opts, long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
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
			option_quite = 1;
			break;
		case EXTRA_OPT_OWNER_AUTH:
			{
				unsigned int size = strlen(optarg);

				cryptfs_tpm2_option_set_owner_auth((uint8_t *)optarg,
								   &size);
				break;
			}
		case EXTRA_OPT_LOCKOUT_AUTH:
			{
				unsigned int size = strlen(optarg);

				cryptfs_tpm2_option_set_lockout_auth((uint8_t *)optarg,
								     &size);
				break;
			}
		case EXTRA_OPT_KEY_SECRET_AUTH:
			{
				unsigned int size = strlen(optarg);

				cryptfs_tpm2_option_set_primary_key_secret((uint8_t *)optarg,
									   &size);
				break;
	                }
		case EXTRA_OPT_PASSPHRASE_SECRET_AUTH:
			{
				unsigned int size = strlen(optarg);

				cryptfs_tpm2_option_set_passphrase_secret((uint8_t *)optarg,
									  &size);
				break;
			}
		case EXTRA_OPT_INTERACTIVE:
			cryptfs_tpm2_option_set_interactive();
			break;
		case 1:
			index = optind;
			return subcommand_parse(argv[0], optarg,
						argc - index + 1,
						argv + index - 1);
		case '?':
		case ':':
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
		info("cryptfs-tpm2 exiting with %d (%s)\n", errno,
		     strerror(errno));
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

	if (!option_quite)
		show_banner();

	return subcommand_run_current();
}