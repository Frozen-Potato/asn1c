#ifndef	ASN1C_COMPAT_H
#define	ASN1C_COMPAT_H

/*
 * Open the arbitrary file by its base name and extension.
 * If opt_tmpname is given, a temporary file will be created and
 * its name returned in (*opt_tmpname).
 * The (*opt_tmpname) should then be subsequently freed by free(3).
 */
FILE *asn1c_open_file(const char *destdir, const char *base_part, const char *extension,
	char **opt_tmpname);

/*
 * Obtain base name and directory name of a path.
 * Some systems have them in <libgen.h> as dirname(3) and basename(3).
 */
const char *a1c_basename(const char *path, const char* destdir);
const char *a1c_dirname(const char *path);

/*
 * Undo journal for the C output (used by asn1c -Fgo, so that a failed run
 * leaves -D as it was). Inactive (all calls are no-ops) until
 * asn1c_txn_begin(). While active, every file the C pass creates is recorded
 * and every file it replaces is first renamed aside to a hidden backup
 * (".<name>.asn1c-bak.<pid>.<n>") in the same directory.
 * asn1c_txn_before_write(): call right before a path is created or replaced;
 *	returns 0, or -1 (diagnostic printed) if the old file cannot be moved.
 * asn1c_txn_created(): record a path that was just created (a symlink).
 * asn1c_txn_rollback(): delete the created files, restore the backups.
 * asn1c_txn_commit(): delete the backups.
 * Both end the journal and return 0, or -1 if a step failed (diagnosed).
 */
void asn1c_txn_begin(void);
int asn1c_txn_before_write(const char *path);
void asn1c_txn_created(const char *path);
int asn1c_txn_rollback(void);
int asn1c_txn_commit(void);

#endif	/* ASN1C_COMPAT_H */
