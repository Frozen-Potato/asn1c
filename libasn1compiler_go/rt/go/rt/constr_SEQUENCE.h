/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_CONSTR_SEQUENCE_H_
#define	_CONSTR_SEQUENCE_H_

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct asn_SEQUENCE_specifics_s {
	/*
	 * Target structure description.
	 */
	unsigned struct_size;	/* Size of the target structure. */
	unsigned ctx_offset;	/* Offset of the asn_struct_ctx_t member */

	/*
	 * Tags to members mapping table (sorted).
	 */
	const asn_TYPE_tag2member_t *tag2el;
	unsigned tag2el_count;

	/*
	 * Optional members of the extensions root (roms) or additions (aoms).
	 * Meaningful for PER.
	 */
	const int *oms;         /* Optional MemberS */
	unsigned roms_count;    /* Root optional members count */
	unsigned aoms_count;    /* Additions optional members count */

	/*
	 * Description of an extensions group.
	 * Root components are clustered at the beginning of the structure,
	 * whereas extensions are clustered at the end. -1 means not extensible.
	 */
	signed first_extension;       /* First extension addition */
} asn_SEQUENCE_specifics_t;


/*
 * A set specialized functions dealing with the SEQUENCE type.
 */
asn_struct_free_f SEQUENCE_free;
asn_struct_print_f SEQUENCE_print;
asn_struct_compare_f SEQUENCE_compare;
asn_constr_check_f SEQUENCE_constraint;
ber_type_decoder_f SEQUENCE_decode_ber;
der_type_encoder_f SEQUENCE_encode_der;
xer_type_decoder_f SEQUENCE_decode_xer;
xer_type_encoder_f SEQUENCE_encode_xer;
#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f SEQUENCE_decode_jer;
jer_type_encoder_f SEQUENCE_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
oer_type_decoder_f SEQUENCE_decode_oer;
oer_type_encoder_f SEQUENCE_encode_oer;
per_type_decoder_f SEQUENCE_decode_uper;
per_type_encoder_f SEQUENCE_encode_uper;
per_type_decoder_f SEQUENCE_decode_aper;
per_type_encoder_f SEQUENCE_encode_aper;
asn_random_fill_f  SEQUENCE_random_fill;
extern asn_TYPE_operation_t asn_OP_SEQUENCE;

/*
 * An extension addition group [[ ]] (a member flagged ATF_EXTENSION_GROUP,
 * whose type is a SEQUENCE) has no encoding of its own in BER, DER and XER:
 * its components are encoded as components of the SEQUENCE or SET holding
 * it (X.690 8.9.2, 8.11.2; X.693 25.2). These helpers serve the codecs of
 * both.
 */
/* The index of the group's component with the BER tag, or -1. */
ssize_t SEQUENCE_group_component_by_tag(const asn_TYPE_member_t *group,
                                        ber_tlv_tag_t tag);
/* BER-decode one component of the group (the one with the tag at ptr, or
 * the one being decoded when resuming) into the group's structure in st,
 * allocating it. */
asn_dec_rval_t SEQUENCE_group_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                                         const asn_TYPE_member_t *group,
                                         void *st, const void *ptr,
                                         size_t size);
/* The index of the group's component whose XER tag (opening or empty) is
 * the tag of tag_size bytes at tag_ptr, or -1. */
ssize_t SEQUENCE_group_component_xer(const asn_TYPE_member_t *group,
                                     const void *tag_ptr, size_t tag_size);
/* The group's structure in st, allocated if absent (NULL on failure). */
void *SEQUENCE_group_struct(const asn_TYPE_member_t *group, void *st);
/* After decoding: whether every group of td present in st has all its
 * mandatory components (the decoders record each one they decode). */
int SEQUENCE_groups_complete(const asn_TYPE_descriptor_t *td, const void *st);
/* Record that component i of the group's structure gptr was decoded. */
void SEQUENCE_group_component_done(const asn_TYPE_member_t *group,
                                   void *gptr, size_t i);
/* XER-encode the components of the group at the level of its holder. */
asn_enc_rval_t SEQUENCE_group_encode_xer(const asn_TYPE_member_t *group,
                                         const void *gptr, int ilevel,
                                         enum xer_encoder_flags_e flags,
                                         asn_app_consume_bytes_f *cb,
                                         void *app_key);

#ifdef __cplusplus
}
#endif

#endif	/* _CONSTR_SEQUENCE_H_ */
