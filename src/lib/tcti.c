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

static void *tcti_handle;

TSS2_TCTI_CONTEXT *
init_tcti_tabrmd(void)
{
	TSS2_TCTI_CONTEXT *ctx;
	size_t size;
	TSS2_RC rc;
#ifndef TSS2_LEGACY_V1
	TSS2_RC (*init)(TSS2_TCTI_CONTEXT *, size_t *, const char *);

	tcti_handle = dlopen("libtss2-tcti-tabrmd.so.0", RTLD_LAZY);
#else
	TSS2_RC (*init)(TSS2_TCTI_CONTEXT *, size_t *);

	tcti_handle = dlopen("libtcti-tabrmd.so.0", RTLD_LAZY);
#endif

	if (!tcti_handle) {
		err("Unable to find out the tabrmd tcti library\n");
		return NULL;
	}

#ifndef TSS2_LEGACY_V1
	init = dlsym(tcti_handle, "Tss2_Tcti_Tabrmd_Init");
#else
	init = dlsym(tcti_handle, "tss2_tcti_tabrmd_init");
#endif
	if (!init) {
		dlclose(tcti_handle);
		return NULL;
	}

#ifndef TSS2_LEGACY_V1
	rc = init(NULL, &size, NULL);
#else
	rc = init(NULL, &size);
#endif
	if (rc != TSS2_RC_SUCCESS) {
		dlclose(tcti_handle);
		err("Unable to get the size of tabrmd tcti context\n");
		return NULL;
	}

	ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
	if (ctx) {
#ifndef TSS2_LEGACY_V1
		rc = init(ctx, &size, NULL);
#else
		rc = init(ctx, &size);
#endif
		if (rc != TSS2_RC_SUCCESS) {
			err("Unable to initialize tabrmd tcti context\n");
			free(ctx);
			ctx = NULL;
			dlclose(tcti_handle);
		}
	}

	return ctx;
}

TSS2_TCTI_CONTEXT *
init_tcti_device(void)
{
#ifndef TSS2_LEGACY_V1
	const char *cfg = "/dev/tpm0";
#else
	TCTI_DEVICE_CONF cfg = {
		.device_path = "/dev/tpm0",
		.logCallback = NULL,
		.logData  = NULL,
	};
#endif
	size_t size;
	TSS2_TCTI_CONTEXT *ctx;
	TSS2_RC rc;

#ifndef TSS2_LEGACY_V1
	rc = Tss2_Tcti_Device_Init(NULL, &size, NULL);
#else
	rc = InitDeviceTcti(NULL, &size, NULL);
#endif
	if (rc != TSS2_RC_SUCCESS) {
		err("Unable to get the size of device tcti context\n");
		return NULL;
	}

	ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
	if (ctx) {
#ifndef TSS2_LEGACY_V1
		rc = Tss2_Tcti_Device_Init(ctx, &size, cfg);
#else
		rc = InitDeviceTcti(ctx, &size, &cfg);
#endif
		if (rc != TSS2_RC_SUCCESS) {
			err("Unable to initialize device tcti context\n");
			free(ctx);
			ctx = NULL;
		}
	}

	return ctx;
}

TSS2_TCTI_CONTEXT *
init_tcti_socket(void)
{
#ifndef TSS2_LEGACY_V1
	const char *cfg = "host=127.0.0.1,port=2321";
#else
	TCTI_SOCKET_CONF cfg = {
		.hostname = DEFAULT_HOSTNAME,
		.port = 2321,
		.logCallback = NULL,
		.logBufferCallback = NULL,
		.logData = NULL,
	};
#endif
	size_t size;
	TSS2_TCTI_CONTEXT *ctx;
	TSS2_RC rc;

#ifndef TSS2_LEGACY_V1
	rc = Tss2_Tcti_Mssim_Init(NULL, &size, cfg);
#else
	rc = InitSocketTcti(NULL, &size, &cfg, 0);
#endif
	if (rc != TSS2_RC_SUCCESS) {
		err("Unable to get the size of socket tcti context\n");
		return NULL;
	}

	ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
	if (ctx) {
#ifndef TSS2_LEGACY_V1
		rc = Tss2_Tcti_Mssim_Init(ctx, &size, cfg);
#else
		rc = InitSocketTcti(ctx, &size, &cfg, 0);
#endif
		if (rc != TSS2_RC_SUCCESS) {
			err("Unable to initialize socket tcti context\n");
			free(ctx);
			ctx = NULL;
		}
	}

	return ctx;
}

TSS2_TCTI_CONTEXT *
cryptfs_tpm2_tcti_init_context(void)
{
	char *tcti_str;

	tcti_str = getenv("TSS2_TCTI");
	if (!tcti_str) {
		tcti_str = "tabrmd";

		info("Use %s as the default tcti interface\n", tcti_str);
	}

	if (!strcmp(tcti_str, "tabrmd"))
		return init_tcti_tabrmd();
	else if (!strcmp(tcti_str, "device"))
		return init_tcti_device();
	else if (!strcmp(tcti_str, "socket"))
		return init_tcti_socket();
	else
		err("Invalid tcti interface specified (%s)\n", tcti_str);

	return NULL;
}

void
cryptfs_tpm2_tcti_teardown_context(TSS2_TCTI_CONTEXT *ctx)
{
#ifndef TSS2_LEGACY_V1
	Tss2_Tcti_Finalize(ctx);
#else
	tss2_tcti_finalize(ctx);
#endif
	free(ctx);

	if (tcti_handle)
		dlclose(tcti_handle);
}
