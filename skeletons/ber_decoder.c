/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>

#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {					\
		size_t num = num_bytes;					\
		ptr = ((const char *)ptr) + num;			\
		size -= num;						\
		consumed_myself += num;					\
	} while(0)
#undef	RETURN
#define	RETURN(_code)	do {						\
		asn_dec_rval_t rval;					\
		rval.code = _code;					\
		if(opt_ctx) opt_ctx->step = step; /* Save context */	\
		if(_code == RC_OK || (opt_ctx && _code != RC_WMORE))	\
			rval.consumed = consumed_myself;		\
		else							\
			rval.consumed = 0;	/* Context-free */	\
		return rval;						\
	} while(0)

/*
 * The BER decoder of any type.
 */
asn_dec_rval_t
ber_decode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *type_descriptor, void **struct_ptr,
           const void *ptr, size_t size) {
    asn_codec_ctx_t s_codec_ctx;

	/*
	 * Stack checker requires that the codec context
	 * must be allocated on the stack.
	 */
	if(opt_codec_ctx) {
		if(opt_codec_ctx->max_stack_size) {
			s_codec_ctx = *opt_codec_ctx;
			opt_codec_ctx = &s_codec_ctx;
		}
	} else {
		/* If context is not given, be security-conscious anyway */
		memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
		s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
		opt_codec_ctx = &s_codec_ctx;
	}

	/*
	 * Invoke type-specific decoder.
	 */
	return type_descriptor->op->ber_decoder(opt_codec_ctx, type_descriptor,
		struct_ptr,	/* Pointer to the destination structure */
		ptr, size,	/* Buffer and its size */
		0		/* Default tag mode is 0 */
		);
}

/*
 * Check the set of <TL<TL<TL...>>> tags matches the definition.
 */
asn_dec_rval_t
ber_check_tags(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
               const void *ptr, size_t size, int tag_mode, int last_tag_form,
               ber_tlv_len_t *last_length, int *opt_tlv_form) {
	return ber_check_tags_eoc(opt_codec_ctx, td, opt_ctx, ptr, size,
		tag_mode, last_tag_form, last_length, opt_tlv_form, 0);
}

/*
 * Same as ber_check_tags(), but with opt_outer_eocs given, a chain of
 * indefinite length TLVs followed by definite length ones is accepted
 * (e.g. [0] EXPLICIT INTEGER as A0 80 02 01 01 00 00, X.690 8.14):
 * *last_length is then the definite length of the last TLV and
 * *opt_outer_eocs the number of end-of-contents octet pairs which follow
 * the value. The caller consumes them (ber_skip_eocs()). In every other
 * case *opt_outer_eocs is set to 0.
 */
asn_dec_rval_t
ber_check_tags_eoc(const asn_codec_ctx_t *opt_codec_ctx,
		const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
		const void *ptr, size_t size, int tag_mode, int last_tag_form,
		ber_tlv_len_t *last_length, int *opt_tlv_form,
		int *opt_outer_eocs) {
    ssize_t consumed_myself = 0;
	ssize_t tag_len;
	ssize_t len_len;
	ber_tlv_tag_t tlv_tag;
	ber_tlv_len_t tlv_len;
	ber_tlv_len_t limit_len = -1;
	int expect_00_terminators = 0;
	int outer_eocs = 0;	/* Indefinite TLVs outside definite ones */
	int tlv_constr = -1;	/* If CHOICE, opt_tlv_form is not given */
	/*
	 * On RC_WMORE nothing is consumed and the chain is read again from
	 * its first tag next time: the number of indefinite length TLVs and
	 * the length limit are not kept in the context.
	 */
	int step = 0;
	int tagno;

	if(opt_outer_eocs) *opt_outer_eocs = 0;

	/*
	 * Make sure we didn't exceed the maximum stack size.
	 */
	if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
		RETURN(RC_FAIL);

	/*
	 * So what does all this implicit skip stuff mean?
	 * Imagine two types,
	 * 	A ::= [5] IMPLICIT	T
	 * 	B ::= [2] EXPLICIT	T
	 * Where T is defined as
	 *	T ::= [4] IMPLICIT SEQUENCE { ... }
	 * 
	 * Let's say, we are starting to decode type A, given the
	 * following TLV stream: <5> <0>. What does this mean?
	 * It means that the type A contains type T which is,
	 * in turn, empty.
	 * Remember though, that we are still in A. We cannot
	 * just pass control to the type T decoder. Why? Because
	 * the type T decoder expects <4> <0>, not <5> <0>.
	 * So, we must make sure we are going to receive <5> while
	 * still in A, then pass control to the T decoder, indicating
	 * that the tag <4> was implicitly skipped. The decoder of T
	 * hence will be prepared to treat <4> as valid tag, and decode
	 * it appropriately.
	 */

	tagno = step	/* The first tag */
		+ (tag_mode==1?-1:0)
		;
	ASN_DEBUG("ber_check_tags(%s, size=%ld, tm=%d, step=%d, tagno=%d)",
		td->name, (long)size, tag_mode, step, tagno);
	/* assert(td->tags_count >= 1) May not be the case for CHOICE or ANY */

	if(tag_mode == 0 && tagno == (int)td->tags_count) {
		/*
		 * This must be the _untagged_ ANY type,
		 * which outermost tag isn't known in advance.
		 * Fetch the tag and length separately.
		 */
		tag_len = ber_fetch_tag(ptr, size, &tlv_tag);
		switch(tag_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}
		tlv_constr = BER_TLV_CONSTRUCTED(ptr);
		len_len = ber_fetch_length(tlv_constr,
			(const char *)ptr + tag_len, size - tag_len, &tlv_len);
		switch(len_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}
		ASN_DEBUG("Advancing %ld in ANY case",
			(long)(tag_len + len_len));
		ADVANCE(tag_len + len_len);
	} else {
		assert(tagno < (int)td->tags_count);	/* At least one loop */
	}
	for((void)tagno; tagno < (int)td->tags_count; tagno++, step++) {

		/*
		 * Fetch and process T from TLV.
		 */
		tag_len = ber_fetch_tag(ptr, size, &tlv_tag);
			ASN_DEBUG("Fetching tag from {%p,%ld}: "
				"len %ld, step %d, tagno %d got %s",
				ptr, (long)size,
				(long)tag_len, step, tagno,
				ber_tlv_tag_string(tlv_tag));
		switch(tag_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		tlv_constr = BER_TLV_CONSTRUCTED(ptr);

		/*
		 * If {I}, don't check anything.
		 * If {I,B,C}, check B and C unless we're at I.
		 */
		if(tag_mode != 0 && step == 0) {
			/*
			 * We don't expect tag to match here.
			 * It's just because we don't know how the tag
			 * is supposed to look like.
			 */
		} else {
		    assert(tagno >= 0);	/* Guaranteed by the code above */
		    if(tlv_tag != td->tags[tagno]) {
			/*
			 * Unexpected tag. Too bad.
			 */
		    	ASN_DEBUG("Expected: %s, "
				"expectation failed (tn=%d, tm=%d)",
				ber_tlv_tag_string(td->tags[tagno]),
				tagno, tag_mode
			);
			RETURN(RC_FAIL);
		    }
		}

		/*
		 * Attention: if there are more tags expected,
		 * ensure that the current tag is presented
		 * in constructed form (it contains other tags!).
		 * If this one is the last one, check that the tag form
		 * matches the one given in descriptor.
		 */
		if(tagno < ((int)td->tags_count - 1)) {
			if(tlv_constr == 0) {
				ASN_DEBUG("tlv_constr = %d, expfail",
					tlv_constr);
				RETURN(RC_FAIL);
			}
		} else {
			if(last_tag_form != tlv_constr
			&& last_tag_form != -1) {
				ASN_DEBUG("last_tag_form %d != %d",
					last_tag_form, tlv_constr);
				RETURN(RC_FAIL);
			}
		}

		/*
		 * Fetch and process L from TLV.
		 */
		len_len = ber_fetch_length(tlv_constr,
			(const char *)ptr + tag_len, size - tag_len, &tlv_len);
		ASN_DEBUG("Fetching len = %ld", (long)len_len);
		switch(len_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		/*
		 * The chain of tags must either contain several indefinite
		 * length TLVs, or several definite length ones, or (with
		 * opt_outer_eocs) indefinite length TLVs enclosing definite
		 * length ones. A definite length TLV enclosing an indefinite
		 * length one is not supported.
		 */
		if(tlv_len == -1) {
			/*
			 * Indefinite length.
			 */
			if(limit_len == -1) {
				expect_00_terminators++;
			} else {
				ASN_DEBUG("Unexpected indefinite length "
					"in a chain of definite lengths");
				RETURN(RC_FAIL);
			}
			ADVANCE(tag_len + len_len);
			continue;
		} else {
			if(expect_00_terminators) {
				if(!opt_outer_eocs) {
					ASN_DEBUG("Unexpected definite length "
						"in a chain of indefinite lengths");
					RETURN(RC_FAIL);
				}
				/* The outer EOCs follow the definite TLV */
				outer_eocs = expect_00_terminators;
				expect_00_terminators = 0;
			}
		}

		/*
		 * Check that multiple TLVs specify ever decreasing length,
		 * which is consistent.
		 */
		if(limit_len == -1) {
			limit_len    = tlv_len + tag_len + len_len;
			if(limit_len < 0) {
				/* Too great tlv_len value? */
				RETURN(RC_FAIL);
			}
		} else if(limit_len != tlv_len + tag_len + len_len) {
			/*
			 * Inner TLV specifies length which is inconsistent
			 * with the outer TLV's length value.
			 */
			ASN_DEBUG("Outer TLV is %ld and inner is %ld",
				(long)limit_len, (long)tlv_len);
			RETURN(RC_FAIL);
		}

		ADVANCE(tag_len + len_len);

		limit_len -= (tag_len + len_len);
		if((ssize_t)size > limit_len) {
			/*
			 * Make sure that we won't consume more bytes
			 * from the parent frame than the inferred limit.
			 */
			size = limit_len;
		}
	}

	if(opt_tlv_form)
		*opt_tlv_form = tlv_constr;
	if(opt_outer_eocs)
		*opt_outer_eocs = outer_eocs;
	if(expect_00_terminators)
		*last_length = -expect_00_terminators;
	else
		*last_length = tlv_len;

	RETURN(RC_OK);
}

/*
 * Check and skip the (eocs) end-of-contents octet pairs at ptr.
 */
ssize_t
ber_skip_eocs(const void *ptr, size_t size, int eocs) {
	const uint8_t *p = (const uint8_t *)ptr;
	size_t need;
	size_t i;

	if(eocs <= 0) return 0;
	need = 2 * (size_t)eocs;
	for(i = 0; i < need && i < size; i++) {
		if(p[i]) return -1;	/* Not an end-of-contents */
	}
	if(size < need) return 0;	/* More data expected */
	return (ssize_t)need;
}
