
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/*
 * Return an allocated memory area.
 */
void *
xmalloc(size_t size)
{
	void *ptr;

	assert(size > 0);

	if ((ptr = malloc(size)) == NULL)
		err(1, NULL);

	return ptr;
}


/*
 * Resize an allocated memory area.
 */
void *
xrealloc(void *ptr, size_t size)
{
	void *newptr;

	assert(ptr != NULL);
	assert(size > 0);

	if ((newptr = realloc(ptr, size)) == NULL)
		err(1, NULL);

	return newptr;
}

/*
 * 4.4BSD err(), warn() functions reimplementation.
 */


void
err(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verr(status, fmt, ap);
	va_end(ap);
}

void
verr(int status, const char *fmt, va_list ap)
{
	int olderrno = errno;

	fprintf(stderr, "csubst: ");
	if (fmt != NULL) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(olderrno));

	exit(status);
}

void
errx(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(status, fmt, ap);
	va_end(ap);
}

void
verrx(int status, const char *fmt, va_list ap)
{
	fprintf(stderr, "csubst: ");
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);

	exit(status);
}

void
warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

void
vwarn(const char *fmt, va_list ap)
{
	int olderrno = errno;

	fprintf(stderr, "csubst: ");
	if (fmt != NULL) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(olderrno));
}

void
warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

void
vwarnx(const char *fmt, va_list ap)
{
	fprintf(stderr, "csubst: ");
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}
