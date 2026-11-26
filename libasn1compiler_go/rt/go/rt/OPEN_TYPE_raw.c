/*
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE_raw.h>
#include <ber_tlv_tag.h>
#include <ber_tlv_length.h>
#if !defined(ASN_DISABLE_PER_SUPPORT)
#include <per_support.h>
#endif  /* !defined(ASN_DISABLE_PER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
#include <jer_decoder.h>
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */

/*
 * The value of an open type whose identifier the object set does not know
 * (see OPEN_TYPE_raw.h). Every decoder keeps the octets it is given as
 * they are and notes its codec; every encoder writes them back, but only
 * for the codec that decoded them.
 */

static xer_type_decoder_f OPEN_TYPE_raw_decode_xer;

asn_TYPE_operation_t asn_OP_OPEN_TYPE_raw = {
	OPEN_TYPE_raw_free,
	OPEN_TYPE_raw_print,
	OPEN_TYPE_raw_compare,
	OPEN_TYPE_raw_decode_ber,
	OPEN_TYPE_raw_encode_der,
	OPEN_TYPE_raw_decode_xer,
	OPEN_TYPE_raw_encode_xer,
#if !defined(ASN_DISABLE_OER_SUPPORT)
	OPEN_TYPE_raw_decode_oer,
	OPEN_TYPE_raw_encode_oer,
#else
	0,
	0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_PER_SUPPORT)
	OPEN_TYPE_raw_decode_uper,
	OPEN_TYPE_raw_encode_uper,
	OPEN_TYPE_raw_decode_aper,
	OPEN_TYPE_raw_encode_aper,
#else
	0, 0, 0, 0,
#endif  /* !defined(ASN_DISABLE_PER_SUPPORT) */
	0,	/* No random fill: there is no type to fill */
	0,	/* Use generic outmost tag fetcher */
#if !defined(ASN_DISABLE_JER_SUPPORT)
	OPEN_TYPE_raw_decode_jer,
	OPEN_TYPE_raw_encode_jer
#else
	0,
	0
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
};

asn_TYPE_descriptor_t asn_DEF_OPEN_TYPE_raw = {
	"OPEN_TYPE_raw",
	"OPEN_TYPE_raw",
	&asn_OP_OPEN_TYPE_raw,
	0, 0, 0, 0,	/* No tags: the value is not a type of its own */
	{ 0, 0, OPEN_TYPE_raw_constraint, 0 },
	0, 0,	/* No members */
	0	/* No specifics */
};

void
OPEN_TYPE_raw_free(const asn_TYPE_descriptor_t *td, void *sptr,
                   enum asn_struct_free_method method) {
	OPEN_TYPE_raw_t *st = (OPEN_TYPE_raw_t *)sptr;

	(void)td;
	if(!st) return;
	FREEMEM(st->raw.buf);
	st->raw.buf = 0;
	st->raw.size = 0;
	st->codec = OPEN_TYPE_RAW_NONE;

	switch(method) {
	case ASFM_FREE_EVERYTHING:
		FREEMEM(st);
		break;
	case ASFM_FREE_UNDERLYING:
		break;
	case ASFM_FREE_UNDERLYING_AND_RESET:
		memset(st, 0, sizeof(*st));
		break;
	}
}

static const char *
raw_codec_name(long codec) {
	switch(codec) {
	case OPEN_TYPE_RAW_BER:  return "BER";
	case OPEN_TYPE_RAW_OER:  return "OER";
	case OPEN_TYPE_RAW_UPER: return "UPER";
	case OPEN_TYPE_RAW_APER: return "APER";
	case OPEN_TYPE_RAW_JER:  return "JER";
	default:                 return "?";
	}
}

int
OPEN_TYPE_raw_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	const char * const h2c = "0123456789ABCDEF";
	const OPEN_TYPE_raw_t *st = (const OPEN_TYPE_raw_t *)sptr;
	const char *name;
	char scratch[3];
	size_t i;

	(void)td;
	(void)ilevel;
	if(!st) return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;

	name = raw_codec_name(st->codec);
	if(cb("<unknown ", 9, app_key) < 0
	   || cb(name, strlen(name), app_key) < 0
	   || cb(":", 1, app_key) < 0)
		return -1;
	for(i = 0; i < st->raw.size; i++) {
		scratch[0] = h2c[(st->raw.buf[i] >> 4) & 0x0F];
		scratch[1] = h2c[st->raw.buf[i] & 0x0F];
		scratch[2] = ' ';
		if(cb(scratch, (i + 1 < st->raw.size) ? 3 : 2, app_key) < 0)
			return -1;
	}
	return (cb(">", 1, app_key) < 0) ? -1 : 0;
}

int
OPEN_TYPE_raw_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                      const void *bptr) {
	const OPEN_TYPE_raw_t *a = (const OPEN_TYPE_raw_t *)aptr;
	const OPEN_TYPE_raw_t *b = (const OPEN_TYPE_raw_t *)bptr;
	size_t common;
	int ret;

	(void)td;
	if(a == b) return 0;
	if(!a) return -1;
	if(!b) return 1;
	if(a->codec != b->codec) return (a->codec < b->codec) ? -1 : 1;
	common = a->raw.size < b->raw.size ? a->raw.size : b->raw.size;
	ret = common ? memcmp(a->raw.buf, b->raw.buf, common) : 0;
	if(ret) return ret < 0 ? -1 : 1;
	if(a->raw.size == b->raw.size) return 0;
	return (a->raw.size < b->raw.size) ? -1 : 1;
}

int
OPEN_TYPE_raw_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                         asn_app_constraint_failed_f *ctfailcb,
                         void *app_key) {
	const OPEN_TYPE_raw_t *st = (const OPEN_TYPE_raw_t *)sptr;

	if(!st) {
		ASN__CTFAIL(app_key, td, sptr, "%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	if(st->codec < OPEN_TYPE_RAW_BER || st->codec > OPEN_TYPE_RAW_JER) {
		ASN__CTFAIL(app_key, td, sptr, "%s: codec not set (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	if((!st->raw.buf && st->raw.size)
	   || (!st->raw.size && st->codec != OPEN_TYPE_RAW_OER)) {
		ASN__CTFAIL(app_key, td, sptr, "%s: no octets (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	return 0;
}

/*
 * Keep a copy of buf[0..size) in *sptr (allocated if NULL), noting codec.
 * Returns 0 on success, -1 on memory failure.
 */
static int
raw_keep(void **sptr, OPEN_TYPE_raw_codec_e codec, const void *buf,
         size_t size) {
	OPEN_TYPE_raw_t *st = (OPEN_TYPE_raw_t *)*sptr;
	uint8_t *copy;

	copy = (uint8_t *)MALLOC(size + 1);
	if(!copy) return -1;
	if(size) memcpy(copy, buf, size);
	copy[size] = '\0';

	if(!st) {
		st = (OPEN_TYPE_raw_t *)CALLOC(1, sizeof(*st));
		if(!st) {
			FREEMEM(copy);
			return -1;
		}
		*sptr = st;
	}
	FREEMEM(st->raw.buf);
	st->raw.buf = copy;
	st->raw.size = size;
	st->codec = codec;
	return 0;
}

/*
 * The octets to write for codec, or NULL when they were decoded by another
 * codec or cannot be a value of it: only OER has empty open type contents
 * (the encoding of NULL); a BER TLV, PER contents and a JSON value never
 * are empty.
 */
static const OPEN_TYPE_raw_t *
raw_for(const void *sptr, OPEN_TYPE_raw_codec_e codec) {
	const OPEN_TYPE_raw_t *st = (const OPEN_TYPE_raw_t *)sptr;
	if(!st || st->codec != codec || (!st->raw.buf && st->raw.size)
	   || (!st->raw.size && codec != OPEN_TYPE_RAW_OER))
		return NULL;
	return st;
}

/* The length of the one TLV at buf, or 0 (more data needed) or -1. */
static ssize_t
raw_ber_tlv_size(const asn_codec_ctx_t *opt_codec_ctx, const void *buf,
                 size_t size) {
	ber_tlv_tag_t tag;
	ssize_t tag_len;
	ssize_t rest_len;

	tag_len = ber_fetch_tag(buf, size, &tag);
	if(tag_len <= 0) return tag_len;
	rest_len = ber_skip_length(opt_codec_ctx, BER_TLV_CONSTRUCTED(buf),
	                           (const char *)buf + tag_len, size - tag_len);
	if(rest_len <= 0) return rest_len;
	return tag_len + rest_len;
}

/*
 * BER: one complete TLV, of any tag, definite or indefinite length. With
 * an EXPLICIT member tag (tag_mode 1, e.g. AUTOMATIC TAGS) the TLV is the
 * one inside it: the enclosing CHOICE writes that tag again on encoding.
 */
asn_dec_rval_t
OPEN_TYPE_raw_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const void *buf_ptr, size_t size, int tag_mode) {
	asn_dec_rval_t rv = {RC_OK, 0};
	const uint8_t *p = (const uint8_t *)buf_ptr;
	size_t outer = 0;	/* the EXPLICIT tag and length before the TLV */
	size_t eoc = 0;		/* the 00 00 after it (indefinite outer length) */
	ber_tlv_len_t outer_len = 0;
	ssize_t tlv_len;

	(void)td;
	if(tag_mode < 0) {
		rv.code = RC_FAIL;	/* an open type is never IMPLICIT */
		return rv;
	}
	if(tag_mode > 0) {
		ber_tlv_tag_t tag;
		ssize_t tl, ll;
		tl = ber_fetch_tag(p, size, &tag);
		if(tl <= 0) {
			rv.code = tl ? RC_FAIL : RC_WMORE;
			return rv;
		}
		if(!BER_TLV_CONSTRUCTED(p)) {
			rv.code = RC_FAIL;
			return rv;
		}
		ll = ber_fetch_length(1, p + tl, size - tl, &outer_len);
		if(ll <= 0) {
			rv.code = ll ? RC_FAIL : RC_WMORE;
			return rv;
		}
		outer = tl + ll;
		if(outer_len < 0) eoc = 2;
	}

	tlv_len = raw_ber_tlv_size(opt_codec_ctx, p + outer, size - outer);
	if(tlv_len <= 0) {
		rv.code = tlv_len ? RC_FAIL : RC_WMORE;
		return rv;
	}
	if(tag_mode > 0) {
		if(eoc) {
			if(size - outer - tlv_len < 2) {
				rv.code = RC_WMORE;
				return rv;
			}
			if(p[outer + tlv_len] || p[outer + tlv_len + 1]) {
				rv.code = RC_FAIL;
				return rv;
			}
		} else if(outer_len != tlv_len) {
			rv.code = RC_FAIL;	/* not exactly one TLV inside */
			return rv;
		}
	}
	if(raw_keep(sptr, OPEN_TYPE_RAW_BER, p + outer, tlv_len)) {
		rv.code = RC_FAIL;
		return rv;
	}
	rv.consumed = outer + tlv_len + eoc;
	return rv;
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
	const OPEN_TYPE_raw_t *st = raw_for(sptr, OPEN_TYPE_RAW_BER);
	asn_enc_rval_t er = {0, 0, 0};

	(void)tag_mode;
	(void)tag;
	if(!st) ASN__ENCODE_FAILED;
	if(cb && st->raw.size && cb(st->raw.buf, st->raw.size, app_key) < 0)
		ASN__ENCODE_FAILED;
	er.encoded = st->raw.size;
	ASN__ENCODED_OK(er);
}

/*
 * XER: an unknown value has no XML form.
 */
static asn_dec_rval_t
OPEN_TYPE_raw_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const char *opt_mname, const void *buf_ptr,
                         size_t size) {
	asn_dec_rval_t rv = {RC_FAIL, 0};
	(void)opt_codec_ctx;
	(void)td;
	(void)sptr;
	(void)opt_mname;
	(void)buf_ptr;
	(void)size;
	return rv;
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int ilevel, enum xer_encoder_flags_e flags,
                         asn_app_consume_bytes_f *cb, void *app_key) {
	(void)ilevel;
	(void)flags;
	(void)cb;
	(void)app_key;
	ASN__ENCODE_FAILED;
}

#if !defined(ASN_DISABLE_OER_SUPPORT)

/*
 * OER: the open type contents (oer_open_type_get passes exactly them).
 */
asn_dec_rval_t
OPEN_TYPE_raw_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         const asn_oer_constraints_t *constraints, void **sptr,
                         const void *ptr, size_t size) {
	asn_dec_rval_t rv = {RC_OK, 0};

	(void)opt_codec_ctx;
	(void)td;
	(void)constraints;
	if(raw_keep(sptr, OPEN_TYPE_RAW_OER, ptr, size)) {
		rv.code = RC_FAIL;
		return rv;
	}
	rv.consumed = size;
	return rv;
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_oer(const asn_TYPE_descriptor_t *td,
                         const asn_oer_constraints_t *constraints,
                         const void *sptr, asn_app_consume_bytes_f *cb,
                         void *app_key) {
	const OPEN_TYPE_raw_t *st = raw_for(sptr, OPEN_TYPE_RAW_OER);
	asn_enc_rval_t er = {0, 0, 0};

	(void)constraints;
	if(!st) ASN__ENCODE_FAILED;
	if(cb && st->raw.size && cb(st->raw.buf, st->raw.size, app_key) < 0)
		ASN__ENCODE_FAILED;
	er.encoded = st->raw.size;
	ASN__ENCODED_OK(er);
}

#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

#if !defined(ASN_DISABLE_PER_SUPPORT)

/*
 * PER: the open type contents, every remaining octet (uper_open_type_get /
 * aper_open_type_get pass exactly them, padding included).
 */
static asn_dec_rval_t
raw_decode_per(OPEN_TYPE_raw_codec_e codec, void **sptr,
               asn_per_data_t *pd) {
	asn_dec_rval_t rv = {RC_OK, 0};
	size_t nbits;
	uint8_t *buf;

	if(pd->nbits < pd->nboff || ((pd->nbits - pd->nboff) & 7)) {
		rv.code = RC_FAIL;
		return rv;
	}
	nbits = pd->nbits - pd->nboff;
	buf = (uint8_t *)MALLOC((nbits >> 3) + 1);
	if(!buf) {
		rv.code = RC_FAIL;
		return rv;
	}
	if(nbits && per_get_many_bits(pd, buf, 0, nbits)) {
		FREEMEM(buf);
		rv.code = RC_FAIL;
		return rv;
	}
	if(raw_keep(sptr, codec, buf, nbits >> 3)) rv.code = RC_FAIL;
	FREEMEM(buf);
	return rv;
}

static asn_enc_rval_t
raw_encode_per(const asn_TYPE_descriptor_t *td, const void *sptr,
               OPEN_TYPE_raw_codec_e codec, asn_per_outp_t *po) {
	const OPEN_TYPE_raw_t *st = raw_for(sptr, codec);
	asn_enc_rval_t er = {0, 0, 0};

	if(!st) ASN__ENCODE_FAILED;
	if(st->raw.size && per_put_many_bits(po, st->raw.buf, st->raw.size * 8))
		ASN__ENCODE_FAILED;
	ASN__ENCODED_OK(er);
}

asn_dec_rval_t
OPEN_TYPE_raw_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints,
                          void **sptr, asn_per_data_t *pd) {
	(void)opt_codec_ctx;
	(void)td;
	(void)constraints;
	return raw_decode_per(OPEN_TYPE_RAW_UPER, sptr, pd);
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_uper(const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints,
                          const void *sptr, asn_per_outp_t *po) {
	(void)constraints;
	return raw_encode_per(td, sptr, OPEN_TYPE_RAW_UPER, po);
}

asn_dec_rval_t
OPEN_TYPE_raw_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints,
                          void **sptr, asn_per_data_t *pd) {
	(void)opt_codec_ctx;
	(void)td;
	(void)constraints;
	return raw_decode_per(OPEN_TYPE_RAW_APER, sptr, pd);
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_aper(const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints,
                          const void *sptr, asn_per_outp_t *po) {
	(void)constraints;
	return raw_encode_per(td, sptr, OPEN_TYPE_RAW_APER, po);
}

#endif  /* !defined(ASN_DISABLE_PER_SUPPORT) */

#if !defined(ASN_DISABLE_JER_SUPPORT)

/*
 * JER: the JSON text of one value (OPEN_TYPE_jer_get passes exactly the
 * member's value, already checked by the enclosing object's parser); JSON
 * whitespace around it is not kept.
 */
asn_dec_rval_t
OPEN_TYPE_raw_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         const asn_jer_constraints_t *constraints, void **sptr,
                         const void *buf_ptr, size_t size) {
	asn_dec_rval_t rv = {RC_OK, 0};
	const char *p = (const char *)buf_ptr;
	size_t vs, ve = size;

	(void)opt_codec_ctx;
	(void)td;
	(void)constraints;
	if(!p) {
		rv.code = RC_FAIL;
		return rv;
	}
	vs = jer_whitespace_span(p, size);
	while(ve > vs && (p[ve - 1] == ' ' || p[ve - 1] == '\t'
	                  || p[ve - 1] == '\n' || p[ve - 1] == '\r'))
		ve--;
	if(ve == vs || raw_keep(sptr, OPEN_TYPE_RAW_JER, p + vs, ve - vs)) {
		rv.code = RC_FAIL;
		return rv;
	}
	rv.consumed = size;
	return rv;
}

asn_enc_rval_t
OPEN_TYPE_raw_encode_jer(const asn_TYPE_descriptor_t *td,
                         const asn_jer_constraints_t *constraints,
                         const void *sptr, int ilevel,
                         enum jer_encoder_flags_e flags,
                         asn_app_consume_bytes_f *cb, void *app_key) {
	const OPEN_TYPE_raw_t *st = raw_for(sptr, OPEN_TYPE_RAW_JER);
	asn_enc_rval_t er = {0, 0, 0};

	(void)constraints;
	(void)ilevel;
	(void)flags;
	if(!st) ASN__ENCODE_FAILED;
	if(cb(st->raw.buf, st->raw.size, app_key) < 0) ASN__ENCODE_FAILED;
	er.encoded = st->raw.size;
	ASN__ENCODED_OK(er);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
