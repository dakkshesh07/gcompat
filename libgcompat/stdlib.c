#include <assert.h> /* assert */
#include <limits.h> /* PATH_MAX */
#include <locale.h> /* locale_t */
#include <stddef.h> /* NULL, size_t */
#include <stdlib.h> /* getenv, realpath, strto* */
#include <unistd.h> /* get*id */
#include <fcntl.h> /* for open() */
#include <poll.h> /* for poll() */
#include <stdint.h> /* for uint8_t, uint32_t */
#include <errno.h> /* for ENOSYS */
#include <stdatomic.h> /* for atomic operations */
#include <sys/syscall.h> /* SYS_getrandom */
#include "alias.h"

/**
 * Resolve a pathname, with buffer overflow checking.
 *
 * LSB 5.0: LSB-Core-generic/baselib---realpath-chk-1.html
 */
char *__realpath_chk(const char *path, char *resolved_path, size_t resolved_len)
{
	assert(path != NULL);
	assert(resolved_path != NULL);
	assert(resolved_len >= PATH_MAX);

	return realpath(path, resolved_path);
}

/**
 * Get an environment variable.
 */
char *__secure_getenv(const char *name)
{
	if (geteuid() != getuid() || getegid() != getgid()) {
		return NULL;
	}

	return getenv(name);
}
weak_alias(__secure_getenv, secure_getenv);

/**
 * Underlying function for strtod.
 *
 * "__group shall be 0 or the behavior of __strtod_internal() is undefined."
 *
 * LSB 5.0: LSB-Core-generic/baselib---strtod-internal-1.html
 */
double __strtod_internal(const char *nptr, char **endptr, int group)
{
	assert(group == 0);

	return strtod(nptr, endptr);
}

/**
 * Underlying function for strtof.
 *
 * "__group shall be 0 or the behavior of __strtof_internal() is undefined."
 *
 * LSB 5.0: LSB-Core-generic/baselib---strtof-internal.html
 */
float __strtof_internal(const char *nptr, char **endptr, int group)
{
	assert(group == 0);

	return strtof(nptr, endptr);
}

/**
 * Underlying function for strtol.
 */
long __strtol_internal(const char *nptr, char **endptr, int base, int group)
{
	assert(group == 0);

	return strtol(nptr, endptr, base);
}

/**
 * Underlying function for strtold.
 *
 * "__group shall be 0 or the behavior of __strtold_internal() is undefined."
 *
 * LSB 5.0: LSB-Core-generic/baselib---strtold-internal-1.html
 */
long double __strtold_internal(const char *nptr, char **endptr, int group)
{
	assert(group == 0);

	return strtold(nptr, endptr);
}

/**
 * Convert string value to a long long integer.
 *
 * Some day, when musl supports LC_NUMERIC, we can probably remove this.
 */
long long int strtoll_l(const char *nptr, char **endptr, int base,
                        locale_t locale)
{
	return strtoll(nptr, endptr, base);
}

/**
 * Convert string value to a long long integer.
 *
 * LSB 5.0: LSB-Core-generic/baselib-strtoq-3.html
 */
long long strtoq(const char *nptr, char **endptr, int base)
{
	return strtoll(nptr, endptr, base);
}

/**
 * Convert a string to an unsigned long long.
 *
 * Some day, when musl supports LC_NUMERIC, we can probably remove this.
 */
unsigned long long int strtoull_l(const char *nptr, char **endptr, int base,
                                  locale_t locale)
{
	return strtoull(nptr, endptr, base);
}

/**
 * Convert a string to an unsigned long long.
 *
 * LSB 5.0: LSB-Core-generic/baselib-strtouq-3.html
 */
unsigned long long strtouq(const char *nptr, char **endptr, int base)
{
	return strtoull(nptr, endptr, base);

}

/* ISO C23 function wrappers */
long int __isoc23_strtol(const char *nptr, char **endptr, int base)
{
    return strtol(nptr, endptr, base);
}

unsigned long int __isoc23_strtoul(const char *nptr, char **endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

long long int __isoc23_strtoll(const char *nptr, char **endptr, int base)
{
    return strtoll(nptr, endptr, base);
}

unsigned long long int __isoc23_strtoull(const char *nptr, char **endptr, int base)
{
    return strtoull(nptr, endptr, base);
}

long int __isoc23_strtol_l(const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtol(nptr, endptr, base);
}

unsigned long int __isoc23_strtoul_l(const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtoul(nptr, endptr, base);
}

long long int __isoc23_strtoll_l(const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtoll(nptr, endptr, base);
}

unsigned long long int __isoc23_strtoull_l(const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtoull(nptr, endptr, base);
}

/* Function to handle fatal errors */
static void arc4random_getrandom_failure(void)
{
    write(STDERR_FILENO, "Fatal error: cannot get entropy for arc4random\n", 48);
    abort();
}

/* Function to fill a buffer with random data */
void arc4random_buf(void *p, size_t n)
{
    static atomic_int seen_initialized = ATOMIC_VAR_INIT(0);
    ssize_t l;
    int fd;

    if (n == 0)
        return;

    for (;;) {
        l = syscall(SYS_getrandom, p, n, 0);
        if (l > 0) {
            if ((size_t)l == n)
                return; /* Done reading, success. */
            p = (uint8_t *)p + l;
            n -= l;
            continue; /* Interrupted by a signal; keep going. */
        } else if (l == -1 && errno == ENOSYS) {
            break; /* No syscall, so fallback to /dev/urandom. */
        }
        arc4random_getrandom_failure();
    }

    if (atomic_load(&seen_initialized) == 0) {
        /* Poll /dev/random as an approximation of RNG initialization. */
        struct pollfd pfd = { .events = POLLIN };
        pfd.fd = open("/dev/random", O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (pfd.fd < 0)
            arc4random_getrandom_failure();
        if (poll(&pfd, 1, -1) < 0)
            arc4random_getrandom_failure();
        if (close(pfd.fd) < 0)
            arc4random_getrandom_failure();
        atomic_store(&seen_initialized, 1);
    }

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        arc4random_getrandom_failure();
    for (;;) {
        l = read(fd, p, n);
        if (l <= 0)
            arc4random_getrandom_failure();
        if ((size_t)l == n)
            break; /* Done reading, success. */
        p = (uint8_t *)p + l;
        n -= l;
    }
    if (close(fd) < 0)
        arc4random_getrandom_failure();
}
weak_alias(arc4random_buf, __arc4random_buf);

/* Function to generate a random 32-bit number */
uint32_t arc4random(void)
{
    uint32_t r;
    arc4random_buf(&r, sizeof(r));
    return r;
}
weak_alias(arc4random, __arc4random);