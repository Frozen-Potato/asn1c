/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_JER_DECODER_H_
#define	_JER_DECODER_H_

#include <asn_application.h>
#include <constr_TYPE.h>	/* asn_struct_ctx_t, jer_type_decoder_f */
#include <jer_support.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/*
 * The JER decoder of any ASN.1 type. May be invoked by the application.
 * Decodes CANONICAL-JER and BASIC-JER.
 */
asn_dec_rval_t jer_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of data buffer */
);

/*
 * The type of the type-specific JER decoder function, jer_type_decoder_f,
 * is declared in constr_TYPE.h (it is part of asn_TYPE_operation_t).
 */

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Generalized function for decoding the primitive values.
 * Used by more specialized functions, such as OCTET_STRING_decode_jer_utf8
 * and others. This function should not be used by applications, as its API
 * is subject to changes.
 */
asn_dec_rval_t jer_decode_general(
    const asn_codec_ctx_t *opt_codec_ctx,
    asn_struct_ctx_t *ctx, /* Type decoder context */
    void *struct_key,      /* Treated as opaque pointer */
    const void *buf_ptr, size_t size,
    int (*opt_unexpected_tag_decoder)(void *struct_key, const void *chunk_buf,
                                      size_t chunk_size),
    ssize_t (*body_receiver)(void *struct_key, const void *chunk_buf,
                             size_t chunk_size, int have_more));


/*
 * Fetch the next JER (JSON) token from the stream.
 * The function returns the number of bytes occupied by the chunk type,
 * returned in the _ch_type. The _ch_type is only set (and valid) when
 * the return value is >= 0.
 */
typedef enum pjer_chunk_type {
	PJER_WMORE,     /* Chunk type is not clear, more data expected. */
	PJER_TEXT,	    /* General data */
	PJER_KEY,	    /* Complete JSON key */
    PJER_VALUE,     /* Complete JSON value */
	PJER_DLM	    /* JSON delimiter */
  } pjer_chunk_type_e;
ssize_t jer_next_token(int *stateContext,
	const void *buffer, size_t size, pjer_chunk_type_e *_ch_type);

/*
 * This function checks the buffer for the current token or 
 * against the key name expected to occur.
 */
typedef enum jer_check_sym {
	JCK_BROKEN,	  /* Something is broken */
	JCK_UNKNOWN,  /* Key or delimiter is unknown */	
	JCK_KEY,	  /* Key is OK */
	JCK_COMMA,    /* Delimiter is ',' */
	JCK_OSTART,	  /* Delimiter is '{' */
	JCK_OEND,     /* Delimiter is '}' */
	JCK_ASTART,	  /* Delimiter is '[' */
	JCK_AEND      /* Delimiter is ']' */
} jer_check_sym_e;
jer_check_sym_e jer_check_sym(const void *buf_ptr, int size,
		const char *need_key);

/*
 * Get the number of bytes consisting entirely of JER whitespace characters.
 * RETURN VALUES:
 * >=0:	Number of whitespace characters in the string.
 */
size_t jer_whitespace_span(const void *chunk_buf, size_t chunk_size);


/*
 * Locate the content of a JSON string value that occupies the whole buffer
 * (JSON whitespace around it is allowed). Anything else after the closing
 * quote, an unterminated string, a raw control character or a dangling
 * backslash fail.
 * RETURN VALUES:
 *  0: Success; *content / *content_size delimit the text between the quotes
 *     (escape sequences are NOT interpreted).
 * -1: Not a complete, well-formed JSON string.
 */
int jer_string_span(const void *buf, size_t size, const char **content,
                    size_t *content_size);

/*
 * Interpret the JSON escape sequences of a string content (see above) and
 * produce UTF-8 (JER_UNESC_UTF8), or one byte per character where each
 * character must be U+0000..U+00FF (JER_UNESC_LATIN1).
 * \uXXXX surrogate pairs are combined; a lone surrogate is an error.
 * The result is allocated with MALLOC() and has a courtesy NUL after the
 * *out_size bytes.
 * RETURN VALUES:
 *  0: Success.
 * -1: Malformed content (bad escape, lone surrogate, not Latin-1 where
 *     required) or memory shortage.
 */
enum jer_unescape_mode_e { JER_UNESC_UTF8, JER_UNESC_LATIN1 };
int jer_unescape(const char *content, size_t content_size,
                 enum jer_unescape_mode_e mode, uint8_t **out,
                 size_t *out_size);

/*
 * Helpers of the constructed types (SEQUENCE, SET, CHOICE, SEQUENCE OF,
 * SET OF). They work on a buffer that holds one COMPLETE JSON value, so the
 * constructed decoders never see a partial value; like the primitives they
 * answer RC_WMORE (nothing consumed) when the value is not complete yet.
 * Not for applications: the API is subject to changes.
 *
 * The decoders recurse once per level of JSON nesting, so the nesting depth
 * is limited (JER_MAX_NESTING) instead of measuring the stack: the stack
 * check of the other decoders (ASN__STACK_OVERFLOW_CHECK) relies on the
 * codec context living on the machine stack.
 *
 * Locate the JSON value at the start of the buffer (JSON whitespace before
 * it is skipped). A scalar (number, true, false, null) is complete only when
 * a delimiter or whitespace follows it inside the buffer.
 * RETURN VALUES:
 *  1: *vstart is the first byte of the value, *vend one past its last byte.
 *  0: The value is not complete, more data is needed.
 * -1: Not JSON, or nested deeper than JER_MAX_NESTING.
 */
#define JER_MAX_NESTING 256
int jer_value_span(const void *buf, size_t size, size_t *vstart,
                   size_t *vend);

/* Cursor over the members of one JSON object or the items of one array. */
typedef struct jer_cursor_s {
    const char *p;
    const char *end;
    int first;
} jer_cursor_t;

/* Start iterating the object / array that is the whole buffer. */
int jer_object_open(jer_cursor_t *c, const void *buf, size_t size);
int jer_array_open(jer_cursor_t *c, const void *buf, size_t size);

/*
 * Fetch the next member of the object: the (not unescaped) key text between
 * the quotes and the value, which is delimited exactly (no whitespace).
 * RETURN VALUES:
 *  1: A member is returned.
 *  0: End of the object.
 * -1: Malformed JSON.
 */
int jer_object_next(jer_cursor_t *c, const char **key, size_t *key_size,
                    const char **val, size_t *val_size);

/* The same for the items of an array (1: item, 0: end, -1: malformed). */
int jer_array_next(jer_cursor_t *c, const char **val, size_t *val_size);

/* Whether the key text (see above) is the given name: 1 or 0. */
int jer_key_equals(const char *key, size_t key_size, const char *name);

/*
 * Skip the series of anticipated extensions.
 */
int jer_skip_unknown(jer_check_sym_e scv, ber_tlv_len_t *depth);

#ifdef __cplusplus
}
#endif

#endif	/* !defined(ASN_DISABLE_JER_SUPPORT) */

#endif	/* _JER_DECODER_H_ */
