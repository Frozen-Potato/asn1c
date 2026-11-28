#ifndef	ASN1_PORTABLE_H
#define	ASN1_PORTABLE_H

/*
 * Windows (mingw-w64) stand-ins for the POSIX calls the compiler uses that the
 * Windows C runtime lacks. Everything here is _WIN32 only: on other systems
 * this header declares nothing and the POSIX calls are used as they are.
 * Include it AFTER the system headers, in the files that need it.
 *
 *	realpath(path, NULL)	symlinks and junctions resolved, '/' separators
 *	strndup, mkdtemp, mkstemp
 *	flock(fd, LOCK_EX [| LOCK_NB])	LockFileEx on the file's first byte
 *	rename		replaces an existing file, or an empty directory
 *	mkdir(path, mode)	the mode is ignored
 *	fchmod		no-op (Windows has no permission bits to set)
 *	O_CLOEXEC	_O_NOINHERIT
 *	asn1c_rmtree	nftw(FTW_DEPTH | FTW_PHYS) + remove(), for -Fgo staging
 *	ASN1_PRINTF	format-attribute archetype (all systems)
 *	ASN1_IS_SEP(c)	both '/' and '\\' separate path components
 *	asn1c_win_binmode()	files and stdin/stdout/stderr in binary mode, so
 *		that input and output are not translated (LF stays LF)
 *	asn1c_win_slashes(s)	'\\' -> '/' in place (the code splits on '/')
 *	asn1c_win_exe_dir()	directory of the running .exe, '/' separated
 */
#ifdef	_WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <io.h>
#include <direct.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define	ASN1_IS_SEP(c)	((c) == '/' || (c) == '\\')

char *asn1c_win_realpath(const char *path, char *resolved);
char *asn1c_win_strndup(const char *s, size_t n);
char *asn1c_win_mkdtemp(char *tmpl);
int asn1c_win_mkstemp(char *tmpl);
int asn1c_win_rename(const char *from, const char *to);
int asn1c_win_flock(int fd, int op);
int asn1c_win_rmtree(const char *dir);	/* 0, or -1 with errno */
static inline void	/* inline: enber/unber do not link libasn1common */
asn1c_win_binmode(void) {
	_fmode = _O_BINARY;
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);
}
char *asn1c_win_slashes(char *s);
char *asn1c_win_exe_dir(void);		/* malloc'd, or NULL */

#define	realpath(p, r)	asn1c_win_realpath((p), (r))
#define	strndup		asn1c_win_strndup
#define	mkdtemp		asn1c_win_mkdtemp
#define	mkstemp		asn1c_win_mkstemp
#define	rename		asn1c_win_rename
#define	flock		asn1c_win_flock
#define	mkdir(p, m)	_mkdir(p)
#define	fchmod(fd, m)	((void)(fd), (void)(m), 0)
#ifndef	O_CLOEXEC
#define	O_CLOEXEC	_O_NOINHERIT
#endif
#define	LOCK_EX	2
#define	LOCK_NB	4
#define	LOCK_UN	8

#else	/* !_WIN32 */

#define	ASN1_IS_SEP(c)	((c) == '/')

#endif	/* _WIN32 */

/*
 * Archetype for __attribute__((format(ASN1_PRINTF, n, m))): with mingw-w64 the
 * plain "printf" archetype follows msvcrt (no %zu); the C99 printf family the
 * code is built with (-D__USE_MINGW_ANSI_STDIO=1) is "gnu_printf".
 */
#ifdef	__MINGW32__
#define	ASN1_PRINTF	gnu_printf
#else
#define	ASN1_PRINTF	printf
#endif

#endif	/* ASN1_PORTABLE_H */
