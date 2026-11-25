/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_BER_DECODER_H_
#define	_BER_DECODER_H_

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */
struct asn_codec_ctx_s;		/* Forward declaration */

/*
 * The BER decoder of any type.
 * This function may be invoked directly from the application.
 * Decodes BER, DER and CER data (DER and CER are different subsets of BER).
 *
 * NOTE: Use the der_encode() function (der_encoder.h) to produce encoding
 * which is compliant with ber_decode().
 */
asn_dec_rval_t ber_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of that buffer */
);

/*
 * Type of generic function which decodes the byte stream into the structure.
 */
typedef asn_dec_rval_t(ber_type_decoder_f)(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr,
    const void *buf_ptr, size_t size, int tag_mode);

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Check that all tags correspond to the type definition (as given in head).
 * On return, last_length would contain either a non-negative length of the
 * value part of the last TLV, or the negative number of expected
 * "end of content" sequences. The number may only be negative if the
 * head->last_tag_form is non-zero.
 */
asn_dec_rval_t ber_check_tags(
    const struct asn_codec_ctx_s *opt_codec_ctx, /* codec options */
    const struct asn_TYPE_descriptor_s *type_descriptor,
    asn_struct_ctx_t *opt_ctx, /* saved decoding context */
    const void *ptr, size_t size,
    int tag_mode,      /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
    int last_tag_form, /* {-1,0:1}: any, primitive, constr */
    ber_tlv_len_t *last_length, int *opt_tlv_form /* optional tag form */
);

/*
 * Same as ber_check_tags(), but also accepts indefinite length TLVs
 * enclosing definite length ones (X.690 8.14, e.g. [0] EXPLICIT INTEGER
 * as A0 80 02 01 01 00 00): *last_length is then the length of the last
 * (definite) TLV and *opt_outer_eocs the number of end-of-contents octet
 * pairs which follow its value (0 if none, always set when given).
 */
asn_dec_rval_t ber_check_tags_eoc(
	const struct asn_codec_ctx_s *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor,
	asn_struct_ctx_t *opt_ctx, const void *ptr, size_t size, int tag_mode,
	int last_tag_form, ber_tlv_len_t *last_length, int *opt_tlv_form,
	int *opt_outer_eocs);

/*
 * Check (eocs) end-of-contents octet pairs at ptr: returns 2 * eocs if they
 * are all there, 0 if more data is needed (or eocs is 0), -1 on other data.
 */
ssize_t ber_skip_eocs(const void *ptr, size_t size, int eocs);

#ifdef __cplusplus
}
#endif

#endif	/* _BER_DECODER_H_ */
