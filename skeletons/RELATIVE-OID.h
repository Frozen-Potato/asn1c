/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_RELATIVE_OID_H_
#define	_RELATIVE_OID_H_

#include <OBJECT_IDENTIFIER.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implemented via OBJECT IDENTIFIER */
typedef OBJECT_IDENTIFIER_t RELATIVE_OID_t;

extern asn_TYPE_descriptor_t asn_DEF_RELATIVE_OID;
extern asn_TYPE_operation_t asn_OP_RELATIVE_OID;

asn_struct_print_f RELATIVE_OID_print;
xer_type_decoder_f RELATIVE_OID_decode_xer;
xer_type_encoder_f RELATIVE_OID_encode_xer;
#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f RELATIVE_OID_decode_jer;
jer_type_encoder_f RELATIVE_OID_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
asn_random_fill_f  RELATIVE_OID_random_fill;

#define RELATIVE_OID_free         ASN__PRIMITIVE_TYPE_free
#define RELATIVE_OID_compare      OCTET_STRING_compare
#define RELATIVE_OID_constraint   asn_generic_no_constraint
#define RELATIVE_OID_decode_ber   ber_decode_primitive
#define RELATIVE_OID_encode_der   der_encode_primitive
#define RELATIVE_OID_decode_oer   oer_decode_primitive
#define RELATIVE_OID_encode_oer   oer_encode_primitive
#define RELATIVE_OID_decode_uper  OCTET_STRING_decode_uper
#define RELATIVE_OID_encode_uper  OCTET_STRING_encode_uper
#define RELATIVE_OID_decode_aper  OCTET_STRING_decode_aper
#define RELATIVE_OID_encode_aper  OCTET_STRING_encode_aper

/**********************************
 * Some handy conversion routines *
 **********************************/

/* Write the dotted arcs ("3.2") with cb(); returns the size or -1. */
ssize_t RELATIVE_OID__dump_body(const RELATIVE_OID_t *st,
                                asn_app_consume_bytes_f *cb, void *app_key);

/* See OBJECT_IDENTIFIER_get_arcs() function in OBJECT_IDENTIFIER.h */
ssize_t RELATIVE_OID_get_arcs(const RELATIVE_OID_t *, asn_oid_arc_t *arcs,
                              size_t arcs_count);

/* See OBJECT_IDENTIFIER_set_arcs() function in OBJECT_IDENTIFIER.h */
int RELATIVE_OID_set_arcs(RELATIVE_OID_t *, const asn_oid_arc_t *arcs,
                          size_t arcs_count);

#ifdef __cplusplus
}
#endif

#endif	/* _RELATIVE_OID_H_ */
