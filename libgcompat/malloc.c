/*
 * struct mallinfo pulled from mallinfo.3:
 *
 * Copyright (c) 2012 by Michael Kerrisk <mtk.manpages@gmail.com>
 *
 * Permission is granted to make and distribute verbatim copies of this
 * manual provided the copyright notice and this permission notice are
 * preserved on all copies.
 *
 * Permission is granted to copy and distribute modified versions of this
 * manual under the conditions for verbatim copying, provided that the
 * entire resulting derived work is distributed under the terms of a
 * permission notice identical to this one.
 *
 * Since the Linux kernel and libraries are constantly changing, this
 * manual page may be incorrect or out-of-date.  The author(s) assume no
 * responsibility for errors or omissions, or for damages resulting from
 * the use of the information contained herein.  The author(s) may not
 * have taken the same level of care in the production of this manual,
 * which is licensed free of charge, as they might when working
 * professionally.
 *
 * Formatted or processed versions of this manual, if unaccompanied by
 * the source, must acknowledge the copyright and authors of this work.
 */

#include <malloc.h> /* memalign */
#include <stdlib.h> /* {m,c,re}alloc, free */
#include <string.h> /* memset */
#include <unistd.h> /* sbrk */

#include "alias.h" /* alias */

struct mallinfo {
	int arena;    /* Non-mmapped space allocated (bytes) */
	int ordblks;  /* Number of free chunks */
	int smblks;   /* Number of free fastbin blocks */
	int hblks;    /* Number of mmapped regions */
	int hblkhd;   /* Space allocated in mmapped regions (bytes) */
	int usmblks;  /* Maximum total allocated space (bytes) */
	int fsmblks;  /* Space in freed fastbin blocks (bytes) */
	int uordblks; /* Total allocated space (bytes) */
	int fordblks; /* Total free space (bytes) */
	int keepcost; /* Top-most, releasable space (bytes) */
};

struct mallinfo2 {
    size_t arena;    /* non-mmapped space allocated from system */
    size_t ordblks;  /* number of free chunks */
    size_t smblks;   /* number of fastbin blocks */
    size_t hblks;    /* number of mmapped regions */
    size_t hblkhd;   /* space in mmapped regions */
    size_t usmblks;  /* always 0, preserved for backwards compatibility */
    size_t fsmblks;  /* space available in freed fastbin blocks */
    size_t uordblks; /* total allocated space */
    size_t fordblks; /* total free space */
    size_t keepcost; /* top-most, releasable (via malloc_trim) space */
};

void *__libc_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}
alias(__libc_calloc, __calloc);

void __libc_free(void *ptr)
{
	free(ptr);
}
alias(__libc_free, __free);

void *__libc_malloc(size_t size)
{
	return malloc(size);
}
alias(__libc_malloc, __malloc);

void *__libc_memalign(size_t align, size_t len)
{
	void *result = NULL;
	if (posix_memalign(&result, align, len) != 0)
		return NULL;
	return result;
}
alias(__libc_memalign, __memalign);

void *__libc_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}
alias(__libc_realloc, __realloc);

void *__sbrk(intptr_t increment)
{
	return sbrk(increment);
}

struct mallinfo mallinfo(void)
{
	struct mallinfo info;
	memset(&info, 0, sizeof(info));
	return info;
}

struct mallinfo2 mallinfo2(void) {
    struct mallinfo2 info2;
    memset(&info2, 0, sizeof(info2));
    return info2;
}
alias(mallinfo2, __mallinfo2);

int malloc_trim(size_t pad)
{
	/* This concept doesn't really map to musl's malloc */
	return 0;
}

void mtrace(void)
{
	/* Not implemented on purpose. */
	return;
}

void muntrace(void)
{
	/* Not implemented on purpose. */
	return;
}
