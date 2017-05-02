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

int option_quite;
char *option_lockout_auth;
bool option_no_da = false;

static uint8_t owner_auth[sizeof(TPMU_HA)];
static unsigned int owner_auth_size;

int
cryptfs_tpm2_option_set_owner_auth(uint8_t *buf, unsigned int *buf_size)
{
	if (!buf || !buf_size || !*buf_size)
		return EXIT_FAILURE;

	owner_auth_size = sizeof(owner_auth);

	if (owner_auth_size > *buf_size)
		owner_auth_size = *buf_size;
	else {
		warn("The authorization value for owner hierarchy is "
		     "no more than %d characters\n", owner_auth_size);

		*buf_size = owner_auth_size;
	}

	memcpy(owner_auth, buf, owner_auth_size);

	return EXIT_SUCCESS;
}

int
cryptfs_tpm2_option_get_owner_auth(uint8_t *buf, unsigned int *buf_size)
{
	if (!buf_size)
		return EXIT_FAILURE;

	unsigned int size;

	if (owner_auth_size > *buf_size) {
		size = *buf_size;
		if (!*buf_size)
			*buf_size = size;
	} else {
		size = owner_auth_size;
		*buf_size = size;
	}

	memcpy(buf, owner_auth, size);

	return EXIT_SUCCESS;
}
