#include "asn1_portable.h"

#ifdef	_WIN32

#define	WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

/* GetLastError() -> errno, for the codes these calls can produce. */
static int
win_errno(DWORD e) {
	switch(e) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_NAME:
	case ERROR_BAD_NETPATH:
	case ERROR_BAD_PATHNAME:
		return ENOENT;
	case ERROR_ACCESS_DENIED:
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:
		return EACCES;
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_DIR_NOT_EMPTY:
		return ENOTEMPTY;
	case ERROR_DIRECTORY:
		return ENOTDIR;
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_FILENAME_EXCED_RANGE:
		return ENAMETOOLONG;
	default:
		return EIO;
	}
}

char *
asn1c_win_realpath(const char *path, char *resolved) {
	HANDLE h;
	DWORD n;
	char *buf, *p, *res;

	if(resolved) { errno = EINVAL; return NULL; }	/* only (path, NULL) */
	h = CreateFileA(path, 0,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if(h == INVALID_HANDLE_VALUE) {
		errno = win_errno(GetLastError());
		return NULL;
	}
	n = GetFinalPathNameByHandleA(h, NULL, 0, VOLUME_NAME_DOS);
	buf = n ? malloc((size_t)n + 1) : NULL;
	if(!buf || GetFinalPathNameByHandleA(h, buf, n + 1, VOLUME_NAME_DOS) == 0) {
		errno = buf ? win_errno(GetLastError()) : ENOMEM;
		CloseHandle(h);
		free(buf);
		return NULL;
	}
	CloseHandle(h);
	/* "\\?\C:\x" -> "C:/x", "\\?\UNC\h\s" -> "//h/s" */
	p = buf;
	if(strncmp(p, "\\\\?\\UNC\\", 8) == 0) {
		p += 6;
		*p = '\\';
	} else if(strncmp(p, "\\\\?\\", 4) == 0) {
		p += 4;
	}
	res = strdup(p);
	free(buf);
	if(res) {
		for(p = res; *p; p++)
			if(*p == '\\') *p = '/';
	} else {
		errno = ENOMEM;
	}
	return res;
}

char *
asn1c_win_strndup(const char *s, size_t n) {
	size_t len = 0;
	char *r;
	while(len < n && s[len]) len++;
	r = malloc(len + 1);
	if(!r) return NULL;
	memcpy(r, s, len);
	r[len] = '\0';
	return r;
}

/* Replace the trailing XXXXXX of tmpl with a name that did not exist: call
 * try(name) until it returns something other than EEXIST. */
static int
win_unique(char *tmpl, int (*try)(char *, void *), void *arg) {
	static const char alnum[] =
		"abcdefghijklmnopqrstuvwxyz0123456789";
	static unsigned long serial;
	size_t len = strlen(tmpl);
	char *x;
	int attempt;
	int r = -1;

	if(len < 6 || strcmp(tmpl + len - 6, "XXXXXX") != 0) {
		errno = EINVAL;
		return -1;
	}
	x = tmpl + len - 6;
	for(attempt = 0; attempt < 1000; attempt++) {
		LARGE_INTEGER pc;
		uint64_t v;
		int i;
		QueryPerformanceCounter(&pc);
		v = (uint64_t)pc.QuadPart * 6364136223846793005ULL
			+ GetCurrentProcessId() * 2654435761ULL
			+ (uint64_t)(++serial) * 1442695040888963407ULL;
		for(i = 0; i < 6; i++) {
			v ^= v >> 29;
			v *= 0xbf58476d1ce4e5b9ULL;
			x[i] = alnum[(v >> 33) % (sizeof(alnum) - 1)];
		}
		r = try(tmpl, arg);
		if(r >= 0 || errno != EEXIST) return r;
	}
	return r;
}

static int
try_dir(char *name, void *arg) {
	(void)arg;
	return _mkdir(name);
}

char *
asn1c_win_mkdtemp(char *tmpl) {
	return win_unique(tmpl, try_dir, NULL) == 0 ? tmpl : NULL;
}

static int
try_file(char *name, void *arg) {
	(void)arg;
	return _open(name, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY | _O_NOINHERIT,
		_S_IREAD | _S_IWRITE);
}

int
asn1c_win_mkstemp(char *tmpl) {
	return win_unique(tmpl, try_file, NULL);
}

/* rename(2): replaces an existing file; replaces an existing EMPTY directory
 * by a directory (RemoveDirectory first, so not one atomic step). */
int
asn1c_win_rename(const char *from, const char *to) {
	DWORD fa = GetFileAttributesA(from);
	DWORD ta = GetFileAttributesA(to);

	if(fa == INVALID_FILE_ATTRIBUTES) {
		errno = win_errno(GetLastError());
		return -1;
	}
	if(ta != INVALID_FILE_ATTRIBUTES
	&& (ta & FILE_ATTRIBUTE_DIRECTORY)
	&& (fa & FILE_ATTRIBUTE_DIRECTORY)) {
		if(!RemoveDirectoryA(to)) {
			errno = win_errno(GetLastError());
			return -1;
		}
	}
	if(!MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		errno = win_errno(GetLastError());
		return -1;
	}
	return 0;
}

/* flock(2) on a regular file: exclusive lock of its first byte, released when
 * the descriptor is closed or the process ends. */
int
asn1c_win_flock(int fd, int op) {
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	OVERLAPPED ov;
	BOOL ok;

	if(h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
	memset(&ov, 0, sizeof(ov));
	if(op & LOCK_UN) {
		ok = UnlockFileEx(h, 0, 1, 0, &ov);
	} else {
		DWORD flags = LOCKFILE_EXCLUSIVE_LOCK;
		if(op & LOCK_NB) flags |= LOCKFILE_FAIL_IMMEDIATELY;
		ok = LockFileEx(h, flags, 0, 1, 0, &ov);
	}
	if(!ok) {
		DWORD e = GetLastError();
		errno = (e == ERROR_LOCK_VIOLATION || e == ERROR_IO_PENDING)
			? EWOULDBLOCK : win_errno(e);
		return -1;
	}
	return 0;
}

/* Delete a directory tree; a link or junction is removed, never followed. */
int
asn1c_win_rmtree(const char *dir) {
	WIN32_FIND_DATAA fd;
	HANDLE h;
	size_t dl = strlen(dir);
	char *pat = malloc(dl + 3);
	int rc = 0;

	if(!pat) { errno = ENOMEM; return -1; }
	sprintf(pat, "%s/*", dir);
	h = FindFirstFileA(pat, &fd);
	free(pat);
	if(h == INVALID_HANDLE_VALUE) {
		errno = win_errno(GetLastError());
		return -1;
	}
	do {
		char *sub;
		if(strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
			continue;
		sub = malloc(dl + 1 + strlen(fd.cFileName) + 1);
		if(!sub) { errno = ENOMEM; rc = -1; break; }
		sprintf(sub, "%s/%s", dir, fd.cFileName);
		if((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
			if(asn1c_win_rmtree(sub) != 0) rc = -1;
		} else {
			if(fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
				SetFileAttributesA(sub, FILE_ATTRIBUTE_NORMAL);
			if((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				? !RemoveDirectoryA(sub) : !DeleteFileA(sub)) {
				errno = win_errno(GetLastError());
				rc = -1;
			}
		}
		free(sub);
	} while(rc == 0 && FindNextFileA(h, &fd));
	FindClose(h);
	if(rc == 0 && !RemoveDirectoryA(dir)) {
		errno = win_errno(GetLastError());
		rc = -1;
	}
	return rc;
}

char *
asn1c_win_slashes(char *s) {
	char *p;
	if(s)
		for(p = s; *p; p++)
			if(*p == '\\') *p = '/';
	return s;
}

char *
asn1c_win_exe_dir(void) {
	char buf[MAX_PATH * 2];
	DWORD n = GetModuleFileNameA(NULL, buf, sizeof(buf));
	char *p;
	if(n == 0 || n >= sizeof(buf)) return NULL;
	asn1c_win_slashes(buf);
	p = strrchr(buf, '/');
	if(!p) return NULL;
	*p = '\0';
	return strdup(buf);
}

#else	/* !_WIN32 */

typedef int asn1_portable_unused;	/* no empty translation unit */

#endif	/* _WIN32 */
