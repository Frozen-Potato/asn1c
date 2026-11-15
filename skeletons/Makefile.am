
CFLAGS = $(filter-out $(CODE_COVERAGE_CFLAGS), @CFLAGS@)

dist_pkgdata_DATA =				\
		${srcdir}/README		\
		${srcdir}/*.[ch]		\
		${srcdir}/file-dependencies

smodsdir=$(pkgdatadir)

nobase_dist_smods_DATA =     \
	standard-modules/README  \
	standard-modules/ASN1-Object-Identifier-Module.asn1 \
	standard-modules/ASN1C-UsefulInformationObjectClasses.asn1


uninstall-local:
	-@echo -n " "
	-rm -f -r $(DESTDIR)$(pkgdatadir)

check_LTLIBRARIES =             \
    libasn1cskeletons.la        \
    libasn1cskeletons_c89.la

libasn1cskeletons_c89_la_CFLAGS = $(SKELETONS_CFLAGS)
libasn1cskeletons_c89_la_SOURCES = $(libasn1cskeletons_la_SOURCES)

# JER is opt-in (see asn_system.h). The test library is built with it ON so
# that tests/tests-skeletons can exercise the JER support code. The c89
# libraries and converter-example keep the default (JER compiled out), which
# also checks that the jer_* sources compile to nothing under strict C89.
# Exception: the -m32 library below is JER-ON, for check-32-JER-support.
libasn1cskeletons_la_CFLAGS = $(TESTSUITE_CFLAGS) -DASN_ENABLE_JER_SUPPORT
libasn1cskeletons_la_SOURCES =                  \
    ANY.c ANY.h                                 \
    ANY_jer.c                                   \
    BIT_STRING.c BIT_STRING.h                   \
    BIT_STRING_oer.c                            \
    BIT_STRING_jer.c                            \
    BMPString.c BMPString.h                     \
    BMPString_jer.c                             \
    BOOLEAN.c BOOLEAN.h                         \
    BOOLEAN_jer.c                               \
    ENUMERATED.c ENUMERATED.h                   \
    ENUMERATED_jer.c                            \
    GeneralString.c GeneralString.h             \
    GeneralizedTime.c GeneralizedTime.h         \
    GeneralizedTime_jer.c                       \
    GraphicString.c GraphicString.h             \
    IA5String.c IA5String.h                     \
    INTEGER.c INTEGER.h                         \
    INTEGER_oer.c                               \
    INTEGER_jer.c                               \
    ISO646String.c ISO646String.h               \
    NULL.c NULL.h                               \
    NULL_jer.c                                  \
    NativeEnumerated.c NativeEnumerated.h       \
    NativeEnumerated_oer.c                      \
    NativeEnumerated_jer.c                      \
    NativeInteger.c NativeInteger.h             \
    NativeInteger_oer.c                         \
    NativeInteger_jer.c                         \
    NativeReal.c NativeReal.h                   \
    NativeReal_jer.c                            \
    NumericString.c NumericString.h             \
    OBJECT_IDENTIFIER.c OBJECT_IDENTIFIER.h     \
    OBJECT_IDENTIFIER_jer.c                     \
    OCTET_STRING.c OCTET_STRING.h               \
    OCTET_STRING_oer.c                          \
    OCTET_STRING_jer.c                          \
    OPEN_TYPE.c OPEN_TYPE.h OPEN_TYPE_oer.c     \
    OPEN_TYPE_jer.c                             \
    ObjectDescriptor.c ObjectDescriptor.h       \
    PrintableString.c PrintableString.h         \
    REAL.c REAL.h                               \
    REAL_jer.c                                  \
    RELATIVE-OID.c RELATIVE-OID.h               \
    RELATIVE-OID_jer.c                          \
    T61String.c T61String.h                     \
    TeletexString.c TeletexString.h             \
    UTCTime.c UTCTime.h                         \
    UTCTime_jer.c                               \
    UTF8String.c UTF8String.h                   \
    UniversalString.c UniversalString.h         \
    UniversalString_jer.c                       \
    VideotexString.c VideotexString.h           \
    VisibleString.c VisibleString.h             \
    asn_SEQUENCE_OF.c asn_SEQUENCE_OF.h         \
    asn_SET_OF.c asn_SET_OF.h                   \
    asn_application.c asn_application.h         \
    asn_system.h asn_codecs.h                   \
    asn_codecs_prim.c asn_codecs_prim.h         \
    asn_codecs_prim_jer.c                       \
    asn_internal.h asn_internal.c               \
    asn_bit_data.c asn_bit_data.h               \
    asn_random_fill.c asn_random_fill.h         \
    ber_decoder.c ber_decoder.h                 \
    ber_tlv_length.c ber_tlv_length.h           \
    ber_tlv_tag.c ber_tlv_tag.h                 \
    constr_CHOICE.c constr_CHOICE.h             \
    constr_CHOICE_jer.c                         \
    constr_CHOICE_oer.c                         \
    constr_SEQUENCE.c constr_SEQUENCE.h         \
    constr_SEQUENCE_jer.c                       \
    constr_SEQUENCE_oer.c                       \
    constr_SEQUENCE_OF.c constr_SEQUENCE_OF.h   \
    constr_SEQUENCE_OF_jer.c                    \
    constr_SET.c constr_SET.h                   \
    constr_SET_jer.c                            \
    constr_SET_OF.c constr_SET_OF.h             \
    constr_SET_OF_jer.c                         \
    constr_SET_OF_oer.c                         \
    constr_TYPE.c constr_TYPE.h                 \
    constraints.c constraints.h                 \
    der_encoder.c der_encoder.h                 \
    oer_decoder.c oer_decoder.h                 \
    oer_encoder.c oer_encoder.h                 \
    oer_support.c oer_support.h                 \
    per_decoder.c per_decoder.h                 \
    per_encoder.c per_encoder.h                 \
    per_opentype.c per_opentype.h               \
    per_support.c per_support.h                 \
    xer_decoder.c xer_decoder.h                 \
    xer_encoder.c xer_encoder.h                 \
    xer_support.c xer_support.h                 \
    jer_decoder.c jer_decoder.h                 \
    jer_encoder.c jer_encoder.h                 \
    jer_support.c jer_support.h

check_PROGRAMS =                    \
    check-converter_example         \
    check-converter_c89_example
LDADD = -lm

check_converter_example_CFLAGS = $(TESTSUITE_CFLAGS) -DNO_ASN_PDU
check_converter_example_SOURCES = converter-example.c
check_converter_example_LDADD = libasn1cskeletons.la

check_converter_c89_example_CFLAGS = $(SKELETON_CFLAGS) -DNO_ASN_PDU
check_converter_c89_example_SOURCES = converter-example.c
check_converter_c89_example_LDADD = libasn1cskeletons_c89.la

if EXPLICIT_M32
check_LTLIBRARIES += libasn1cskeletons_c89_32.la
libasn1cskeletons_c89_32_la_CFLAGS = $(CFLAGS_M32) -Wno-format -DASN_ENABLE_JER_SUPPORT
libasn1cskeletons_c89_32_la_SOURCES = $(libasn1cskeletons_la_SOURCES)

check_PROGRAMS += check-converter_c89_32_example
check_converter_c89_32_example_CFLAGS = $(CFLAGS_M32) -DNO_ASN_PDU
check_converter_c89_32_example_SOURCES = converter-example.c
check_converter_c89_32_example_LDADD = libasn1cskeletons_c89_32.la
endif

