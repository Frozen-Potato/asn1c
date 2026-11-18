/*
 * go_swap.c — atomic exchange of two directory entries for the Go backend.
 *
 * Kept apart from go_emit.c, which sets _XOPEN_SOURCE and so does not see
 * the Linux system call interface. Linux 3.15+ (renameat2 RENAME_EXCHANGE):
 * both names exist at every instant. Elsewhere, or on a file system that does
 * not support it, the call fails with ENOSYS / EINVAL / ENOTSUP and the caller
 * falls back to two renames.
 */
#define _GNU_SOURCE
#include <errno.h>
#ifdef __linux__
#include <fcntl.h>              /* AT_FDCWD */
#include <unistd.h>             /* syscall */
#include <sys/syscall.h>        /* SYS_renameat2 */
#endif

int go_dir_exchange(const char *a, const char *b);

int
go_dir_exchange(const char *a, const char *b) {
#if defined(__linux__) && defined(SYS_renameat2)
    /* RENAME_EXCHANGE is (1 << 1) in <linux/fs.h>; spelled out so that
     * older C libraries without the renameat2 wrapper build too. */
    return (int)syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 2u);
#else
    (void)a;
    (void)b;
    errno = ENOSYS;
    return -1;
#endif
}
