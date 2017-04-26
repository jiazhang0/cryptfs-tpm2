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

#define DEFAULT_DELAY_SECOND		1UL
#define DEFAULT_TIMEOUT_SECOND		5UL

static unsigned long opt_delay = DEFAULT_DELAY_SECOND;
static unsigned long opt_timeout = DEFAULT_TIMEOUT_SECOND;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s wait <args>\n", prog);
	info_cont("\nargs:\n");
	info_cont("  --delay, -d: (optional) The delay (in second) "
		  "before attempting to connecting resourcemgr. "
		  "Default: %ld\n", DEFAULT_DELAY_SECOND);
	info_cont("  --timeout, -t: (optional) The timeout (in second) "
		  "upon awaiting resourcemgr. 0 indicates infinite wait. "
		  "Default: %ld\n", DEFAULT_TIMEOUT_SECOND);
}

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 'd':
		opt_delay = strtoul(optarg, NULL, 0);
                break;
	case 't':
		opt_timeout = strtoul(optarg, NULL, 0);
                break;
	default:
		return -1;
	}

	return 0;
}

static int
run_wait(char *prog)
{
	TSS2_TCTI_CONTEXT *context = NULL;
	unsigned long total_delay = 0;

	while (1) {
		context = cryptfs_tpm2_util_init_tcti_context();
		if (context) {
			info("resourcemgr is getting ready\n");
			break;
		}

		sleep(opt_delay);
		total_delay += opt_delay;

		info("Already waited for resourcemgr %ld seconds\n",
		     total_delay);

		if (opt_timeout && total_delay >= opt_timeout) {
			info("Timeout upon awaiting resourcemgr\n");
			break;
		}
	}

	if (context)
		cryptfs_tpm2_util_teardown_tcti_context(context);

	return 0;
}

static struct option long_opts[] = {
	{ "delay", required_argument, NULL, 'd' },
	{ "timeout", required_argument, NULL, 't' },
	{ 0 },	/* NULL terminated */
};

subcommand_t subcommand_wait = {
	.name = "wait",
	.optstring = "-d:t:",
	.long_opts = long_opts,
	.parse_arg = parse_arg,
	.show_usage = show_usage,
	.run = run_wait,
};
