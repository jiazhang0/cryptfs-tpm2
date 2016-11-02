/*
 * Linux-specific wrappers
 *
 * Copyright (c) 2016, Wind River Systems, Inc.
 * All rights reserved.
 *
 * See "LICENSE" for license terms.
 *
 * Author:
 *	  Lans Zhang <jia.zhang@windriver.com>
 */

#include <eee.h>

#ifndef O_LARGEFILE
  #define O_LARGEFILE		0
#endif

int
load_file(const char *file_path, uint8_t **out, unsigned long *out_len)
{
	FILE *fp;
	uint8_t *buf;
	unsigned int size;
	int ret;

	dbg("Opening file %s ...\n", file_path);

	fp = fopen(file_path, "rb");
	if (!fp) {
		err("Failed to open file %s.\n", file_path);
		return -1;
	}

	if (fseek(fp, 0, SEEK_END)) {
		ret = -1;
		err("Failed to seek the end of file.\n");
		goto err;
	}

	size = ftell(fp);
	if (!size) {
		ret = -1;
		err("Empty file.\n");
		goto err;
	}

	rewind(fp);

	buf = (uint8_t *)malloc(size);
	if (!buf) {
		ret = -1;
		err("Failed to allocate memory for file.\n");
		goto err;
	}

	if (fread(buf, size, 1, fp) != 1) {
		ret = -1;
		err("Failed to read file.\n");
		free(buf);
	} else {
		*out = buf;
		*out_len = size;
		ret = 0;
	}

err:
	fclose(fp);

	return ret;
}

int
save_output_file(const char *file_path, uint8_t *buf, unsigned long size)
{
	FILE *fp;

	dbg("Saving output file %s ...\n", file_path);

	fp = fopen(file_path, "w");
	if (!fp) {
		err("Failed to create output file.\n");
		return -1;
	}

	if (fwrite(buf, size, 1, fp) != 1) {
		fclose(fp);
		err("Failed to write output file.\n");
		return -1;
	}

	fclose(fp);

	return 0;
}

size_t
eee_strlen(const char *s)
{
	return strlen(s);
}

char *
eee_strcpy(char *dest, const char *src)
{
	return strcpy(dest, src);
}

char *
eee_strncpy(char *dest, const char *src, size_t n)
{
	return strncpy(dest, src, n);
}

int
eee_strcmp(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

int
eee_memcmp(const void *s1, const void *s2, unsigned long n)
{
	return memcmp(s1, s2, (size_t)n);
}

void *
eee_memcpy(void *dst, const void *src, unsigned long size)
{
	return memcpy(dst, src, (size_t)size);
}

void *
eee_memset(void *s, int c, unsigned long n)
{
	return memset(s, c, (size_t)n);
}

void *
eee_malloc(unsigned long size)
{
	return malloc((size_t)size);
}

void *
eee_mrealloc(void *buf, unsigned long size, unsigned long new_size)
{
	return realloc(buf, (size_t)new_size);
}

void *
eee_mrealloc_aligned(void *buf, unsigned long size, unsigned long *new_size)
{
	return eee_mrealloc(buf, size, *new_size);
}

void
eee_mfree(void *buf)
{
	free(buf);
}