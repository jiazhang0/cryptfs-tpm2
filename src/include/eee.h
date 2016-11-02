/*
 * External Executable Environment (EEE)
 *
 * Copyright (c) 2016, Wind River Systems, Inc.
 * All rights reserved.
 *
 * See "LICENSE" for license terms.
 *
 * Author:
 *	  Lans Zhang <jia.zhang@windriver.com>
 */

#ifndef EEE_H
#define EEE_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/limits.h>

typedef unsigned int		bool;

#define gettid()		syscall(__NR_gettid)

#define __pr__(level, fmt, ...)	\
	do {	\
		time_t __t__ = time(NULL);	\
		struct tm __loc__;	\
		localtime_r(&__t__, &__loc__);	\
		char __buf__[64]; \
		strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);	\
		fprintf(stderr, "%s: [" #level "] " fmt, __buf__, ##__VA_ARGS__);	\
	} while (0)

#define die(fmt, ...)	\
	do {	\
		__pr__(FAULT, fmt, ##__VA_ARGS__);	\
		exit(EXIT_FAILURE);	\
	} while (0)

#ifdef DEBUG
  #define dbg(fmt, ...)	\
	do {	\
		__pr__(DEBUG, fmt, ##__VA_ARGS__);	\
	} while (0)

  #define dbg_cont(fmt, ...)	\
	do {	\
		fprintf(stdout, fmt, ##__VA_ARGS__);	\
	} while (0)
#else
  #define dbg(fmt, ...)
  #define dbg_cont(fmt, ...)
#endif

#define info(fmt, ...)	\
	do {	\
		__pr__(INFO, fmt, ##__VA_ARGS__);	\
	} while (0)

#define info_cont(fmt, ...)	\
	fprintf(stdout, fmt, ##__VA_ARGS__)

#define warn(fmt, ...)	\
	do {	\
		__pr__(WARNING, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err(fmt, ...)	\
	do {	\
		__pr__(ERROR, fmt, ##__VA_ARGS__);	\
	} while (0)

#define err_cont(fmt, ...)	\
	fprintf(stdout, fmt, ##__VA_ARGS__)

extern size_t
eee_strlen(const char *s);

extern char *
eee_strcpy(char *dest, const char *src);

extern char *
eee_strncpy(char *dest, const char *src, size_t n);

extern int
eee_strcmp(const char *s1, const char *s2);

extern int
eee_memcmp(const void *s1, const void *s2, unsigned long n);

extern void *
eee_memcpy(void *dst, const void *src, unsigned long size);

void *
eee_memset(void *s, int c, unsigned long n);

extern void *
eee_malloc(unsigned long size);

extern void *
eee_mrealloc(void *buf, unsigned long size, unsigned long new_size);

extern void *
eee_mrealloc_aligned(void *buf, unsigned long size, unsigned long *new_size);

extern void
eee_mfree(void *buf);

int
save_output_file(const char *file_path, uint8_t *buf, unsigned long size);

#endif	/* EEE_H */