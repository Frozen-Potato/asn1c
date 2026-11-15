/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <stdio.h>
#include <errno.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_encoder.h>

/*
 * The JER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
jer_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
           enum jer_encoder_flags_e jer_flags,
           asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
	asn_enc_rval_t tmper;

	if(!td || !td->op || !td->op->jer_encoder || !sptr) goto cb_failed;

	tmper = td->op->jer_encoder(td, 0, sptr, 0, jer_flags, cb, app_key);
	if(tmper.encoded == -1) return tmper;
	er.encoded += tmper.encoded;

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}


ssize_t
jer_write_escaped_codepoint(uint32_t codepoint, asn_app_consume_bytes_f *cb,
                            void *key) {
	static const char hex[] = "0123456789abcdef";
	char bytes[6];
	size_t length;

	if(!cb || codepoint > 0x10ffff
	   || (codepoint >= 0xd800 && codepoint <= 0xdfff))
		return -1;
	if(codepoint < 0x20) {
		bytes[0] = '\\';
		switch(codepoint) {
		case '\b': bytes[1] = 'b'; length = 2; break;
		case '\t': bytes[1] = 't'; length = 2; break;
		case '\n': bytes[1] = 'n'; length = 2; break;
		case '\f': bytes[1] = 'f'; length = 2; break;
		case '\r': bytes[1] = 'r'; length = 2; break;
		default:
			bytes[1] = 'u'; bytes[2] = '0'; bytes[3] = '0';
			bytes[4] = hex[(codepoint >> 4) & 0xf];
			bytes[5] = hex[codepoint & 0xf];
			length = 6;
			break;
		}
	} else if(codepoint == '"' || codepoint == '\\') {
		bytes[0] = '\\'; bytes[1] = (char)codepoint; length = 2;
	} else if(codepoint < 0x80) {
		bytes[0] = (char)codepoint; length = 1;
	} else if(codepoint < 0x800) {
		bytes[0] = (char)(0xc0 | (codepoint >> 6));
		bytes[1] = (char)(0x80 | (codepoint & 0x3f));
		length = 2;
	} else if(codepoint < 0x10000) {
		bytes[0] = (char)(0xe0 | (codepoint >> 12));
		bytes[1] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
		bytes[2] = (char)(0x80 | (codepoint & 0x3f));
		length = 3;
	} else {
		bytes[0] = (char)(0xf0 | (codepoint >> 18));
		bytes[1] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
		bytes[2] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
		bytes[3] = (char)(0x80 | (codepoint & 0x3f));
		length = 4;
	}
	return cb(bytes, length, key) < 0 ? -1 : (ssize_t)length;
}

/*
 * This is a helper function for jer_fprint, which directs all incoming data
 * into the provided file descriptor.
 */
static int
jer__print2fp(const void *buffer, size_t size, void *app_key) {
	FILE *stream = (FILE *)app_key;

	if(fwrite(buffer, 1, size, stream) != size)
		return -1;

	return 0;
}

int
jer_fprint(FILE *stream, const asn_TYPE_descriptor_t *td, const void *sptr) {
	asn_enc_rval_t er = {0,0,0};

	if(!stream) stream = stdout;
	if(!td || !sptr)
		return -1;

	er = jer_encode(td, sptr, JER_F, jer__print2fp, stream);
	if(er.encoded == -1)
		return -1;

	return fflush(stream);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
