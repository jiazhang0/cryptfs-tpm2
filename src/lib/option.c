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
static uint8_t primary_key_secret[sizeof(TPMU_HA)];
static unsigned int primary_key_secret_size;
static uint8_t passphrase_secret[sizeof(TPMU_HA)];
static unsigned int passphrase_secret_size;

#define option_set_value(name, buf, buf_size, obj, obj_size) \
do {	\
	if (!buf || !buf_size || !*buf_size) \
		return EXIT_FAILURE; \
	\
	obj_size = sizeof(owner_auth);	\
	\
	if (obj_size > *buf_size)	\
		obj_size = *buf_size;	\
	else {	\
		warn("The authorization value for " name " is "	\
		     "no more than %d characters\n", obj_size);	\
		\
		*buf_size = obj_size;	\
	}	\
	\
	memcpy(obj, buf, obj_size);	\
	\
	return EXIT_SUCCESS;	\
} while (0)

#define option_get_value(name, buf, buf_size, obj, obj_size) \
do {	\
	if (!buf_size)	\
		return EXIT_FAILURE;	\
	\
	unsigned int __size;	\
	\
	if (obj_size > *buf_size) {	\
		__size = *buf_size;	\
		if (!*buf_size)	\
			*buf_size = obj_size;	\
	} else {	\
		__size = obj_size;	\
		*buf_size = __size;	\
	}	\
	\
	memcpy(buf, obj, __size);	\
	\
	return EXIT_SUCCESS;	\
} while (0)

int
cryptfs_tpm2_option_set_owner_auth(uint8_t *buf, unsigned int *buf_size)
{
	option_set_value("owner hierarchy", buf, buf_size, owner_auth,
			 owner_auth_size);
}

int
cryptfs_tpm2_option_get_owner_auth(uint8_t *buf, unsigned int *buf_size)
{
	option_get_value("owner hierarchy", buf, buf_size, owner_auth,
			 owner_auth_size);
}

int
cryptfs_tpm2_option_set_primary_key_secret(uint8_t *buf,
					   unsigned int *buf_size)
{
	option_set_value("primary key", buf, buf_size, primary_key_secret,
			 primary_key_secret_size);
}

int
cryptfs_tpm2_option_get_primary_key_secret(uint8_t *buf,
					   unsigned int *buf_size)
{
	option_get_value("primary key", buf, buf_size, primary_key_secret,
			 primary_key_secret_size);
}

int
cryptfs_tpm2_option_set_passphrase_secret(uint8_t *buf,
					  unsigned int *buf_size)
{
	option_set_value("passphrase", buf, buf_size, passphrase_secret,
			 passphrase_secret_size);
}

int
cryptfs_tpm2_option_get_passphrase_secret(uint8_t *buf,
					  unsigned int *buf_size)
{
	option_get_value("passphrase", buf, buf_size, passphrase_secret,
			 passphrase_secret_size);
}
