/*
 * go_rows.h — the name-row surface go_names.c hands the glue (go_glue*.c)
 * and constructor (go_ctor.c) emitters: a read-only view of the name bag,
 * valid until go_generate returns, plus the package-dir and module-path
 * lookups go_ctor.c uses. Defined in go_names.c.
 */
#ifndef GO_ROWS_H
#define GO_ROWS_H

int go_names_rows_n(void);
const char *go_names_row_module(int i);
const char *go_names_row_goname(int i);
const char *go_names_row_rawcid(int i);
const char *go_names_row_kind(int i);
const char *go_names_row_field_type(int i);
const char *go_names_row_sf_owner(int i);
const char *go_names_row_slice_elem(int i);
const char *go_names_row_intval(int i);
const char *go_names_row_gotype(int i);
int go_names_row_is_struct(int i);
const char *go_names_row_leaf_underlying(int i);

/* module pkg dir (malloc'd) + import-path head, for go_ctor.c */
char *go_ctor_pkg_of(const char *module);
const char *go_ctor_module_path(void);

#endif /* GO_ROWS_H */
