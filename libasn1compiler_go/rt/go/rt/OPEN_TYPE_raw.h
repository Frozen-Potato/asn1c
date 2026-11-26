/*
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef ASN_OPEN_TYPE_RAW_H
#define ASN_OPEN_TYPE_RAW_H

#include <asn_application.h>
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The value of an open type whose identifier is not in the extensible
 * object set that governs it (X.681 14.10: a receiver of an extensible set
 * may accept such a value). asn1c -fopen-type-unknown adds it to such an
 * open type as the alternative <T>_PR_unknown (member "unknown").
 *
 * The value is kept as it was received: the open type contents (the
 * octets inside the PER / OER open type wrapper, the whole BER TLV, the
 * JSON text of the JER value), together with the codec that decoded it.
 * It can only be encoded again with that same codec (DER and BER count
 * as one: the octets are written back as they are). The value cannot be
 * canonicalized, so der_encode() gives DER only if the received octets
 * were DER.
 */
typedef enum OPEN_TYPE_raw_codec {
	OPEN_TYPE_RAW_NONE = 0,	/* not set: encoding fails */
	OPEN_TYPE_RAW_BER  = 1,	/* BER / DER: one complete TLV */
	OPEN_TYPE_RAW_OER  = 2,	/* OER: the open type contents */
	OPEN_TYPE_RAW_UPER = 3,	/* unaligned PER: the open type contents */
	OPEN_TYPE_RAW_APER = 4,	/* aligned PER: the open type contents */
	OPEN_TYPE_RAW_JER  = 5	/* JER: the JSON text of the value */
} OPEN_TYPE_raw_codec_e;

typedef struct OPEN_TYPE_raw {
	long codec;		/* OPEN_TYPE_raw_codec_e */
	OCTET_STRING_t raw;	/* the encoding, as received */
} OPEN_TYPE_raw_t;

extern asn_TYPE_descriptor_t asn_DEF_OPEN_TYPE_raw;
extern asn_TYPE_operation_t asn_OP_OPEN_TYPE_raw;

asn_struct_free_f OPEN_TYPE_raw_free;
asn_struct_print_f OPEN_TYPE_raw_print;
asn_struct_compare_f OPEN_TYPE_raw_compare;
asn_constr_check_f OPEN_TYPE_raw_constraint;
ber_type_decoder_f OPEN_TYPE_raw_decode_ber;
der_type_encoder_f OPEN_TYPE_raw_encode_der;
xer_type_encoder_f OPEN_TYPE_raw_encode_xer;
#if !defined(ASN_DISABLE_OER_SUPPORT)
oer_type_decoder_f OPEN_TYPE_raw_decode_oer;
oer_type_encoder_f OPEN_TYPE_raw_encode_oer;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_PER_SUPPORT)
per_type_decoder_f OPEN_TYPE_raw_decode_uper;
per_type_encoder_f OPEN_TYPE_raw_encode_uper;
per_type_decoder_f OPEN_TYPE_raw_decode_aper;
per_type_encoder_f OPEN_TYPE_raw_encode_aper;
#endif  /* !defined(ASN_DISABLE_PER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f OPEN_TYPE_raw_decode_jer;
jer_type_encoder_f OPEN_TYPE_raw_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */

#ifdef __cplusplus
}
#endif

#endif	/* ASN_OPEN_TYPE_RAW_H */
