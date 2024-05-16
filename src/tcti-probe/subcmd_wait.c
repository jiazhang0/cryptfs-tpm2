/*
 * Copyright (c) 2024, Alibaba Cloud
 * Copyright (c) 2016-2023, Wind River Systems, Inc.
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

#define DEFAULT_DELAY_MSEC		100UL
#define DEFAULT_TIMEOUT_MSEC		5000UL

static unsigned long opt_delay_ms = DEFAULT_DELAY_MSEC;
static unsigned long opt_timeout_ms = DEFAULT_TIMEOUT_MSEC;

static void
show_usage(char *prog)
{
	info_cont("\nUsage: %s <options> wait <args>\n", prog);
	info_cont("\nargs:\n");
	info_cont("  --delay, -d:\n"
		  "    (optional)The delay (in millisecond) before\n"
		  "    attempting to connecting the resource manager.\n"
		  "    Default: %ld\n", DEFAULT_DELAY_MSEC);
	info_cont("  --timeout, -t:\n"
		  "    (optional) The timeout (in millisecond) upon\n"
		  "    awaiting the resource manager. 0 indicates infinite "
		  "wait.\n"
		  "    Default: %ld\n", DEFAULT_TIMEOUT_MSEC);
}

static int
parse_arg(int opt, char *optarg)
{
	switch (opt) {
	case 'd':
		opt_delay_ms = strtoul(optarg, NULL, 0);
                break;
	case 't':
		opt_timeout_ms = strtoul(optarg, NULL, 0);
                break;
	default:
		return -1;
	}

	if (!opt_delay_ms) {
		err("Invalid setting of -d option\n");
		return -1;
	}

	return 0;
}

static void
accurate_delay_begin(void)
{
	struct sched_param param;
	int policy = SCHED_RR;

	param.sched_priority = sched_get_priority_max(policy);
	sched_setscheduler(0, policy, &param);
}

static void
accurate_delay(unsigned long delay_ms)
{
	struct timespec req;

	req.tv_sec = delay_ms / 1000;
	delay_ms %= 1000;
	req.tv_nsec = delay_ms * 1000000;

	while (1) {
		struct timespec rem;
		int err;

		err = nanosleep(&req, &rem);
		if (!err || errno != EINTR)
			break;

		req = rem;
	}
}

static int
run_wait(char *prog)
{
	TSS2_TCTI_CONTEXT *context = NULL;
	unsigned long total_delay_ms = 0;
	int ret = EXIT_SUCCESS;

	accurate_delay_begin();

	while (1) {
		context = cryptfs_tpm2_tcti_init_context();
		if (context) {
			info("The resource manager is getting ready\n");
			break;
		}

		if (total_delay_ms + opt_delay_ms > opt_timeout_ms &&
		    opt_timeout_ms)
			opt_delay_ms = opt_timeout_ms - total_delay_ms;
		accurate_delay(opt_delay_ms);
		total_delay_ms += opt_delay_ms;

		dbg("Already waited for the resource manager %ld "
		    "millisecond\n", total_delay_ms);

		if (total_delay_ms >= opt_timeout_ms && opt_timeout_ms) {
			err("Timeout upon awaiting the resource manager\n");
			ret = EXIT_FAILURE;
			break;
		}
	}

	if (context)
		cryptfs_tpm2_tcti_teardown_context(context);

	return ret;
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
