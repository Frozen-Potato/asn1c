/*
 * asn1cgo error model.
 */
#include "err.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int asn1cgo_fail(asn1cgo_err *e, asn1cgo_err_code c, const char *type,
                 const char *field, const char *msg_fmt, ...) {
    if (e) {
        e->code = c;
        e->type_name = type;
        e->field = field;
        e->msg[0] = '\0';
        if (msg_fmt) {
            va_list ap;
            va_start(ap, msg_fmt);
            (void)vsnprintf(e->msg, sizeof(e->msg), msg_fmt, ap);
            va_end(ap);
        }
    }
    return (int)c;
}

size_t asn1cgo_err_msg_len(const asn1cgo_err *e) {
    if (!e) return 0;
    return strlen(e->msg);
}
