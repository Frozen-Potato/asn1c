#include "asn1c_internal.h"
#include "asn1c_compat.h"

/* Normally file permissions are (DEFFILEMODE & ~umask(2)) */
#ifndef	DEFFILEMODE	/* Normally in <sys/stat.h> */

#ifdef	_WIN32
#define	DEFFILEMODE	(S_IREAD|S_IWRITE)
#define REASONABLE_FILE_MODE    DEFFILEMODE
#else
#define	DEFFILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define REASONABLE_FILE_MODE    (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#endif
#else   /* !DEFFILEMODE */
#ifdef	_WIN32
#define REASONABLE_FILE_MODE    DEFFILEMODE
#else
#define REASONABLE_FILE_MODE    (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#endif
#endif

#ifdef _WIN32
int mkstemp(char *template) {
	char *tmpFN = _mktemp(template);
	if(tmpFN)
		return open(tmpFN, O_CREAT | O_EXCL | O_WRONLY, DEFFILEMODE);
	else
		return -1;
}
#undef HAVE_MKSTEMPS
#endif

#ifdef	HAVE_MKSTEMPS
#undef	mkstemp
#define	mkstemp(foo)	mkstemps(foo, 0)
#endif

FILE *
asn1c_open_file(const char *destdir, const char *name, const char *ext,
                char **opt_tmpname) {
    char fname[PATH_MAX];
	int created = 1;
#ifndef	_WIN32
	struct stat sb;
#endif
	FILE *fp;
	int ret;
	int fd;

	/*
	 * Compute filenames.
	 */
    ret = snprintf(fname, sizeof(fname), "%s%s%s%s", destdir ? destdir : "",
                   name, ext, opt_tmpname ? ".XXXXXX" : "");
    assert(ret > 0 && ret < (ssize_t)sizeof(fname));

    if(opt_tmpname) {
		/*
		 * Create temporary file.
		 */
		fd = mkstemp(fname);
#ifndef	_WIN32
        if(fd != -1) {
            /* fchmod() does not respect umask */
            (void)fchmod(fd, REASONABLE_FILE_MODE);
        }
#endif
	} else {
		/*
		 * Create specified file, or open the old one.
		 */
		if(asn1c_txn_before_write(fname))
			return NULL;
		fd = open(fname, O_CREAT | O_EXCL | O_WRONLY, DEFFILEMODE);
		if(fd == -1 && errno == EEXIST) {
			fd = open(fname, O_WRONLY, DEFFILEMODE);
			created = 0;
		}
	}
	if(fd == -1) {
        struct stat st;
        if(destdir && stat(destdir, &st) == -1) {
            fprintf(stderr, "%s: No such directory\n", destdir);
            return NULL;
        } else {
            perror(fname);
            return NULL;
        }
	}

#ifndef	_WIN32
	/*
	 * Check sanity.
	 */
	if(fstat(fd, &sb) || !S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s: Not a regular file\n", fname);
		if(created) unlink(fname);
		close(fd);
		return NULL;
	}

	if(ftruncate(fd, 0) == -1) {
		fprintf(stderr, "%s: ftruncate failed: %s\n",
                        fname, strerror(errno));
		if(created) unlink(fname);
        return NULL;
    }
#else
	_chsize(fd, 0);
#endif	/* _WIN32 */

	/*
	 * Convert file descriptor into file pointer.
	 */
	fp = fdopen(fd, "w");
	if(fp == NULL) {
		if(created) unlink(fname);
		close(fd);
		return NULL;
	}

	/* Return the temporary file name */
	if(opt_tmpname) {
		*opt_tmpname = strdup(fname);
		if(*opt_tmpname) {
			/* Successfull */
		} else {
			if(created) unlink(fname);
			fclose(fp);
			return NULL;
		}
	}

	return fp;
}

/*
 * Undo journal (see asn1c_compat.h).
 */
#ifdef	_WIN32
#define	lstat	stat
#endif

struct txn_ent {
	char *path;
	char *backup;	/* NULL: the file did not exist before this run */
};
static struct txn_ent *txn_ents;
static size_t txn_count;
static size_t txn_size;
static int txn_active;

void
asn1c_txn_begin(void) {
	txn_active = 1;
}

static int
txn_known(const char *path) {
	size_t i;
	for(i = 0; i < txn_count; i++)
		if(strcmp(txn_ents[i].path, path) == 0) return 1;
	return 0;
}

static int
txn_add(const char *path, char *backup) {
	if(txn_count == txn_size) {
		size_t nsize = txn_size ? 2 * txn_size : 64;
		struct txn_ent *n = realloc(txn_ents, nsize * sizeof(*n));
		if(!n) return -1;
		txn_ents = n;
		txn_size = nsize;
	}
	txn_ents[txn_count].path = strdup(path);
	if(!txn_ents[txn_count].path) return -1;
	txn_ents[txn_count].backup = backup;
	txn_count++;
	return 0;
}

/* ".<name>.asn1c-bak.<pid>.<n>" next to path (never ends in .c/.h). */
static char *
txn_backup_name(const char *path) {
	static unsigned long serial;
	const char *base = strrchr(path, '/');
	size_t dlen = base ? (size_t)(base - path) + 1 : 0;
	size_t len = strlen(path) + 64;
	char *b = malloc(len);
	if(!b) return NULL;
	snprintf(b, len, "%.*s.%s.asn1c-bak.%ld.%lu", (int)dlen, path,
			 path + dlen, (long)getpid(), serial++);
	return b;
}

int
asn1c_txn_before_write(const char *path) {
	struct stat sb;
	char *backup;

	if(!txn_active || txn_known(path))
		return 0;
	if(lstat(path, &sb) != 0) {
		if(errno != ENOENT) {
			perror(path);
			return -1;
		}
		if(txn_add(path, NULL) == 0) return 0;
		fprintf(stderr, "%s: out of memory\n", path);
		return -1;
	}
	if(!S_ISREG(sb.st_mode)
#ifndef	_WIN32
	&& !S_ISLNK(sb.st_mode)
#endif
	)
		return 0;	/* not ours to move: the write itself fails */
	backup = txn_backup_name(path);
	if(!backup) {
		fprintf(stderr, "%s: out of memory\n", path);
		return -1;
	}
	if(rename(path, backup) != 0) {
		fprintf(stderr, "%s: cannot move aside to %s: %s\n", path, backup,
				strerror(errno));
		free(backup);
		return -1;
	}
	if(txn_add(path, backup) != 0) {
		(void)rename(backup, path);
		free(backup);
		fprintf(stderr, "%s: out of memory\n", path);
		return -1;
	}
	return 0;
}

void
asn1c_txn_created(const char *path) {
	if(txn_active && !txn_known(path) && txn_add(path, NULL) != 0)
		fprintf(stderr, "%s: out of memory (not recorded for undo)\n", path);
}

static void
txn_end(void) {
	size_t i;
	for(i = 0; i < txn_count; i++) {
		free(txn_ents[i].path);
		free(txn_ents[i].backup);
	}
	free(txn_ents);
	txn_ents = NULL;
	txn_count = txn_size = 0;
	txn_active = 0;
}

int
asn1c_txn_rollback(void) {
	int rc = 0;
	size_t i;
	for(i = txn_count; i-- > 0;) {
		struct txn_ent *e = &txn_ents[i];
		if(e->backup) {
			if(rename(e->backup, e->path) != 0) {
				fprintf(stderr, "%s: cannot restore from %s: %s\n", e->path,
						e->backup, strerror(errno));
				rc = -1;
			}
		} else if(unlink(e->path) != 0 && errno != ENOENT) {
			fprintf(stderr, "%s: cannot remove: %s\n", e->path,
					strerror(errno));
			rc = -1;
		}
	}
	txn_end();
	return rc;
}

int
asn1c_txn_commit(void) {
	int rc = 0;
	size_t i;
	for(i = 0; i < txn_count; i++) {
		struct txn_ent *e = &txn_ents[i];
		if(e->backup && unlink(e->backup) != 0) {
			fprintf(stderr, "%s: cannot remove: %s\n", e->backup,
					strerror(errno));
			rc = -1;
		}
	}
	txn_end();
	return rc;
}

const char *
a1c_basename(const char *path, const char *destdir) {
	static char strbuf[PATH_MAX];
	const char *pend;
	const char *name;
	char *sbuf = strbuf;

	if(destdir) {
		strncpy(strbuf, destdir, PATH_MAX - 1);
		strbuf[PATH_MAX - 1] = '\0';
		sbuf = strbuf + strlen(strbuf);
	}
	pend = path + strlen(path);
	if(pend == path) {
		strcpy(sbuf, ".");
		return strbuf;
	}

	/* Skip tailing slashes */
	for(pend--; pend > path && *pend == '/'; pend--);

	if(pend == path && *path == '/') {
		strcpy(sbuf, "/");
		return strbuf;
	}

	for(name = pend; name > path && name[-1] != '/'; name--);

	if((pend - name) >= (int)sizeof(strbuf) - 1) {
		errno = ENAMETOOLONG;
		return 0;
	}

	memcpy(sbuf, name, pend - name + 1);
	sbuf[pend - name + 1] = '\0';

	return strbuf;
}


const char *
a1c_dirname(const char *path) {
	static char strbuf[PATH_MAX];
	const char *pend;
	const char *last = 0;
	int in_slash = 0;

	/* One-pass determination of the last char of the pathname */
	for(pend = path; ; pend++) {
		switch(*pend) {
		case '\0': break;
		case '/':
			if(!in_slash) {
				last = pend;
				in_slash = 1;
			}
			continue;
		default:
			if(in_slash) in_slash = 0;
			continue;
		}
		break;
	}

	if(last <= path) {
		strcpy(strbuf, *path == '/' ? "/" : ".");
		return strbuf;
	}

	if(!last) {
		strcpy(strbuf, "/");
		return strbuf;
	}

	if((last - path) >= (int)sizeof(strbuf)) {
		errno = ENAMETOOLONG;
		return 0;
	}

	memcpy(strbuf, path, last - path);
	strbuf[last - path] = '\0';

	return strbuf;
}

