/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_BIT_STRING_H_
#define	_BIT_STRING_H_

#include <OCTET_STRING.h>	/* Some help from OCTET STRING */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BIT_STRING_s {
	uint8_t *buf;	/* BIT STRING body */
	size_t size;	/* Size of the above buffer */

	int bits_unused;/* Unused trailing bits in the last octet (0..7) */

	asn_struct_ctx_t _asn_ctx;	/* Parsing across buffer boundaries */
} BIT_STRING_t;

extern asn_TYPE_descriptor_t asn_DEF_BIT_STRING;
extern asn_TYPE_operation_t asn_OP_BIT_STRING;
extern asn_OCTET_STRING_specifics_t asn_SPC_BIT_STRING_specs;
/* A BIT STRING written with a NamedBitList ({ a(0), b(3) }): same as above,
 * but its trailing 0 bits are not significant (has_named_bits). */
extern asn_TYPE_descriptor_t asn_DEF_BIT_STRING_named;
extern asn_OCTET_STRING_specifics_t asn_SPC_BIT_STRING_named_specs;

asn_struct_print_f BIT_STRING_print;	/* Human-readable output */
asn_struct_compare_f BIT_STRING_compare;
asn_constr_check_f BIT_STRING_constraint;
xer_type_encoder_f BIT_STRING_encode_xer;
#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f BIT_STRING_decode_jer;
jer_type_encoder_f BIT_STRING_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
oer_type_decoder_f BIT_STRING_decode_oer;
oer_type_encoder_f BIT_STRING_encode_oer;
per_type_decoder_f BIT_STRING_decode_uper;
per_type_encoder_f BIT_STRING_encode_uper;
per_type_encoder_f BIT_STRING_encode_aper;
asn_random_fill_f  BIT_STRING_random_fill;

#define BIT_STRING_free              OCTET_STRING_free
#define BIT_STRING_decode_ber        OCTET_STRING_decode_ber
#define BIT_STRING_encode_der        OCTET_STRING_encode_der
#define BIT_STRING_decode_xer        OCTET_STRING_decode_xer_binary
#define BIT_STRING_decode_aper       OCTET_STRING_decode_aper

#ifdef __cplusplus
}
#endif

#endif	/* _BIT_STRING_H_ */
