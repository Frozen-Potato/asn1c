/*
 * JER (X.697) of the primitive types: BOOLEAN, NULL, INTEGER, ENUMERATED,
 * REAL, OCTET STRING, BIT STRING, OBJECT IDENTIFIER, RELATIVE-OID, the
 * time types, the character string types and ANY, in their Native
 * variants too. Built with ASN_ENABLE_JER_SUPPORT.
 *
 * Every vector is encoded in both ATS_JER and ATS_JER_MINIFIED and compared
 * with the expected text, then decoded back (also with extra white space and
 * with the alternative spellings) and compared with the value.
 *
 * The "ours" texts are what asn1c writes. They were generated with the
 * Python package asn1tools 0.169.0 (the JER codec), run once; the test does
 * not need Python. Where asn1tools writes something else, the asn1tools text
 * is the "alt" column (the decoder must accept it as well):
 *   - non-ASCII characters: asn1tools escapes them (é), asn1c writes
 *     the UTF-8 text; DEL (U+007F) likewise;
 *   - minus zero: asn1tools writes the number -0.0, X.697 and asn1c the
 *     string "-0".
 * Not covered by asn1tools (the expected text comes from X.697 and, for
 * float-sized REAL, from a Python float32 round trip): RELATIVE-OID,
 * VideotexString, UTCTime, GeneralizedTime, ANY, T61String, float REAL.
 * asn1tools writes GeneralString, GraphicString and TeletexString as plain
 * JSON strings, as asn1c does (not the hexadecimal text of the original
 * port).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <asn_internal.h>
#include <asn_application.h>
#include <BOOLEAN.h>
#include <NULL.h>
#include <INTEGER.h>
#include <NativeInteger.h>
#include <ENUMERATED.h>
#include <NativeEnumerated.h>
#include <REAL.h>
#include <NativeReal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <OBJECT_IDENTIFIER.h>
#include <RELATIVE-OID.h>
#include <UTCTime.h>
#include <GeneralizedTime.h>
#include <UTF8String.h>
#include <IA5String.h>
#include <PrintableString.h>
#include <VisibleString.h>
#include <NumericString.h>
#include <BMPString.h>
#include <UniversalString.h>
#include <GeneralString.h>
#include <GraphicString.h>
#include <TeletexString.h>
#include <T61String.h>
#include <VideotexString.h>
#include <ObjectDescriptor.h>
#include <ANY.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

#ifdef ASN_DISABLE_JER_SUPPORT
#error This test must be built with ASN_ENABLE_JER_SUPPORT
#endif

enum kind {
    V_BOOL, V_NULL, V_INT, V_NINT, V_ENUM, V_NENUM, V_REAL, V_NREAL,
    V_NREAL4, V_OCT, V_BITS, V_BITSF, V_OID, V_ROID, V_UT, V_GT, V_U8,
    V_IA5, V_PRINT, V_VIS, V_NUM, V_BMP, V_UNI, V_GEN, V_GRAPH, V_TELE,
    V_T61, V_VIDEO, V_OD, V_ANY
};

struct vec {
    int kind;
    const char *spec;    /* How to build the value (see build()) */
    const char *ours;    /* Expected text, both modes */
    const char *alt;     /* Another text that must decode to the same value */
    const char *pretty;  /* Expected ATS_JER text, if it differs from "ours" */
};

static const struct vec vecs[] = {
    { V_BOOL, "1", "true", 0, 0 },
    { V_BOOL, "0", "false", 0, 0 },
    { V_NULL, "", "null", 0, 0 },
    { V_INT, "00", "0", 0, 0 },
    { V_INT, "01", "1", 0, 0 },
    { V_INT, "FF", "-1", 0, 0 },
    { V_INT, "7F", "127", 0, 0 },
    { V_INT, "0080", "128", 0, 0 },
    { V_INT, "80", "-128", 0, 0 },
    { V_INT, "FF7F", "-129", 0, 0 },
    { V_INT, "00FF", "255", 0, 0 },
    { V_INT, "0100", "256", 0, 0 },
    { V_INT, "FF00", "-256", 0, 0 },
    { V_INT, "00FFFF", "65535", 0, 0 },
    { V_INT, "0080000000", "2147483648", 0, 0 },
    { V_INT, "FF7FFFFFFF", "-2147483649", 0, 0 },
    { V_INT, "7FFFFFFFFFFFFFFF", "9223372036854775807", 0, 0 },
    { V_INT, "8000000000000000", "-9223372036854775808", 0, 0 },
    { V_INT, "008000000000000000", "9223372036854775808", 0, 0 },
    { V_INT, "010000000000000000", "18446744073709551616", 0, 0 },
    { V_INT, "FEFFFFFFFFFFFFFFFF", "-18446744073709551617", 0, 0 },
    { V_INT, "018EE90FF6C373E0EE4E3F0AD2", "123456789012345678901234567890", 0, 0 },
    { V_INT, "0100000000000000000000000000000000000000000000000000", "1606938044258990275541962092341162602522202993782792835301376", 0, 0 },
    { V_INT, "FF00000000000000000000000000000000000000000000000000", "-1606938044258990275541962092341162602522202993782792835301376", 0, 0 },
    { V_INT, "FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1606938044258990275541962092341162602522202993782792835301377", 0, 0 },
    { V_NINT, "0", "0", 0, 0 },
    { V_NINT, "1", "1", 0, 0 },
    { V_NINT, "-1", "-1", 0, 0 },
    { V_NINT, "2147483647", "2147483647", 0, 0 },
    { V_NINT, "-2147483648", "-2147483648", 0, 0 },
    { V_NINT, "123456", "123456", 0, 0 },
    { V_ENUM, "0", "\"red\"", 0, 0 },
    { V_NENUM, "0", "\"red\"", 0, 0 },
    { V_ENUM, "1", "\"green\"", 0, 0 },
    { V_NENUM, "1", "\"green\"", 0, 0 },
    { V_ENUM, "5", "\"blue-ish\"", 0, 0 },
    { V_NENUM, "5", "\"blue-ish\"", 0, 0 },
    { V_REAL, "0x0.0p+0", "0.0", 0, 0 },
    { V_NREAL, "0x0.0p+0", "0.0", 0, 0 },
    { V_REAL, "-0x0.0p+0", "\"-0\"", "-0.0", 0 },
    { V_NREAL, "-0x0.0p+0", "\"-0\"", "-0.0", 0 },
    { V_REAL, "0x1.8000000000000p+0", "1.5", 0, 0 },
    { V_NREAL, "0x1.8000000000000p+0", "1.5", 0, 0 },
    { V_REAL, "-0x1.4000000000000p+1", "-2.5", 0, 0 },
    { V_NREAL, "-0x1.4000000000000p+1", "-2.5", 0, 0 },
    { V_REAL, "0x1.249ad2594c37dp+332", "1e+100", 0, 0 },
    { V_NREAL, "0x1.249ad2594c37dp+332", "1e+100", 0, 0 },
    { V_REAL, "0x1.ad7f29abcaf48p-24", "1e-07", 0, 0 },
    { V_NREAL, "0x1.ad7f29abcaf48p-24", "1e-07", 0, 0 },
    { V_REAL, "0x1.9000000000000p+6", "100.0", 0, 0 },
    { V_NREAL, "0x1.9000000000000p+6", "100.0", 0, 0 },
    { V_REAL, "0x1.999999999999ap-4", "0.1", 0, 0 },
    { V_NREAL, "0x1.999999999999ap-4", "0.1", 0, 0 },
    { V_REAL, "0x1.d6f3454800000p+26", "123456789.125", 0, 0 },
    { V_NREAL, "0x1.d6f3454800000p+26", "123456789.125", 0, 0 },
    { V_REAL, "0x1.0f0cf064dd592p+73", "1e+22", 0, 0 },
    { V_NREAL, "0x1.0f0cf064dd592p+73", "1e+22", 0, 0 },
    { V_REAL, "0x1.1c37937e08000p+53", "1e+16", 0, 0 },
    { V_NREAL, "0x1.1c37937e08000p+53", "1e+16", 0, 0 },
    { V_REAL, "0x1.a36e2eb1c432dp-14", "0.0001", 0, 0 },
    { V_NREAL, "0x1.a36e2eb1c432dp-14", "0.0001", 0, 0 },
    { V_REAL, "0x1.4f8b588e368f1p-17", "1e-05", 0, 0 },
    { V_NREAL, "0x1.4f8b588e368f1p-17", "1e-05", 0, 0 },
    { V_REAL, "inf", "\"INF\"", 0, 0 },
    { V_NREAL, "inf", "\"INF\"", 0, 0 },
    { V_REAL, "-inf", "\"-INF\"", 0, 0 },
    { V_NREAL, "-inf", "\"-INF\"", 0, 0 },
    { V_REAL, "nan", "\"NaN\"", 0, 0 },
    { V_NREAL, "nan", "\"NaN\"", 0, 0 },
    { V_REAL, "0x1.b69b4ba630f35p+56", "1.2345678901234568e+17", 0, 0 },
    { V_NREAL, "0x1.b69b4ba630f35p+56", "1.2345678901234568e+17", 0, 0 },
    { V_REAL, "0x0.0000000000001p-1022", "5e-324", 0, 0 },
    { V_NREAL, "0x0.0000000000001p-1022", "5e-324", 0, 0 },
    { V_REAL, "0x1.fffffffffffffp+1023", "1.7976931348623157e+308", 0, 0 },
    { V_NREAL, "0x1.fffffffffffffp+1023", "1.7976931348623157e+308", 0, 0 },
    { V_REAL, "0x1.0000000000000p+53", "9007199254740992.0", 0, 0 },
    { V_NREAL, "0x1.0000000000000p+53", "9007199254740992.0", 0, 0 },
    { V_NREAL4, "0x1.99999a0000000p-4", "0.1", 0, 0 },
    { V_NREAL4, "0x1.8000000000000p+0", "1.5", 0, 0 },
    { V_NREAL4, "-0x1.a000000000000p+1", "-3.25", 0, 0 },
    { V_NREAL4, "0x1.0000000000000p+24", "16777216.0", 0, 0 },
    { V_NREAL4, "0x1.fffffe0000000p+127", "3.4028235e+38", 0, 0 },
    { V_NREAL4, "0x1.b7cdfe0000000p-34", "1e-10", 0, 0 },
    { V_NREAL4, "0x1.5555560000000p-2", "0.33333334", 0, 0 },
    { V_NREAL4, "0x1.9000000000000p+6", "100.0", 0, 0 },
    { V_OCT, "", "\"\"", 0, 0 },
    { V_OCT, "00", "\"00\"", 0, 0 },
    { V_OCT, "DEADBEEF", "\"DEADBEEF\"", 0, 0 },
    { V_OCT, "000102030405060708090A0B0C0D0E0F10111213", "\"000102030405060708090A0B0C0D0E0F10111213\"", 0, 0 },
    { V_OCT, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", "\"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF\"", 0, 0 },
    { V_BITS, "/0", "{\"value\":\"\",\"length\":0}", 0, "{\012    \"value\": \"\",\012    \"length\": 0\012}" },
    { V_BITS, "A0/3", "{\"value\":\"A0\",\"length\":3}", 0, "{\012    \"value\": \"A0\",\012    \"length\": 3\012}" },
    { V_BITS, "FF/8", "{\"value\":\"FF\",\"length\":8}", 0, "{\012    \"value\": \"FF\",\012    \"length\": 8\012}" },
    { V_BITS, "ABC0/10", "{\"value\":\"ABC0\",\"length\":10}", 0, "{\012    \"value\": \"ABC0\",\012    \"length\": 10\012}" },
    { V_BITS, "80/1", "{\"value\":\"80\",\"length\":1}", 0, "{\012    \"value\": \"80\",\012    \"length\": 1\012}" },
    { V_BITS, "555555555555555555/72", "{\"value\":\"555555555555555555\",\"length\":72}", 0, "{\012    \"value\": \"555555555555555555\",\012    \"length\": 72\012}" },
    { V_BITSF, "ABC0/12", "\"ABC0\"", 0, 0 },
    { V_BITSF, "00F0/12", "\"00F0\"", 0, 0 },
    { V_OID, "1.2.840.113549", "\"1.2.840.113549\"", 0, 0 },
    { V_OID, "2.5.4.3", "\"2.5.4.3\"", 0, 0 },
    { V_OID, "0.0", "\"0.0\"", 0, 0 },
    { V_OID, "2.999.3", "\"2.999.3\"", 0, 0 },
    { V_OID, "1.3.6.1.4.1.4294967295", "\"1.3.6.1.4.1.4294967295\"", 0, 0 },
    { V_ROID, "8571.3.2", "\"8571.3.2\"", 0, 0 },
    { V_ROID, "0", "\"0\"", 0, 0 },
    { V_ROID, "1.2.3", "\"1.2.3\"", 0, 0 },
    { V_UT, "170101120000Z", "\"170101120000Z\"", 0, 0 },
    { V_UT, "9912312359+0100", "\"9912312359+0100\"", 0, 0 },
    { V_GT, "20170101120000Z", "\"20170101120000Z\"", 0, 0 },
    { V_GT, "20170101120000.5Z", "\"20170101120000.5Z\"", 0, 0 },
    { V_U8, "hello", "\"hello\"", 0, 0 },
    { V_U8, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_U8, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_U8, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_U8, "\342\202\254", "\"\342\202\254\"", "\"\\u20ac\"", 0 },
    { V_U8, "\360\237\230\200", "\"\360\237\230\200\"", "\"\\ud83d\\ude00\"", 0 },
    { V_U8, "", "\"\"", 0, 0 },
    { V_U8, "\001", "\"\\u0001\"", 0, 0 },
    { V_U8, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_U8, "/slash", "\"/slash\"", 0, 0 },
    { V_U8, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_IA5, "hello", "\"hello\"", 0, 0 },
    { V_IA5, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_IA5, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_IA5, "", "\"\"", 0, 0 },
    { V_IA5, "\001", "\"\\u0001\"", 0, 0 },
    { V_IA5, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_IA5, "/slash", "\"/slash\"", 0, 0 },
    { V_IA5, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_PRINT, "hello", "\"hello\"", 0, 0 },
    { V_PRINT, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_PRINT, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_PRINT, "", "\"\"", 0, 0 },
    { V_PRINT, "\001", "\"\\u0001\"", 0, 0 },
    { V_PRINT, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_PRINT, "/slash", "\"/slash\"", 0, 0 },
    { V_PRINT, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_VIS, "hello", "\"hello\"", 0, 0 },
    { V_VIS, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_VIS, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_VIS, "", "\"\"", 0, 0 },
    { V_VIS, "\001", "\"\\u0001\"", 0, 0 },
    { V_VIS, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_VIS, "/slash", "\"/slash\"", 0, 0 },
    { V_VIS, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_NUM, "", "\"\"", 0, 0 },
    { V_NUM, "1", "\"1\"", 0, 0 },
    { V_NUM, "12 3", "\"12 3\"", 0, 0 },
    { V_NUM, "0 9", "\"0 9\"", 0, 0 },
    { V_BMP, "hello", "\"hello\"", 0, 0 },
    { V_BMP, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_BMP, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_BMP, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_BMP, "\342\202\254", "\"\342\202\254\"", "\"\\u20ac\"", 0 },
    { V_BMP, "", "\"\"", 0, 0 },
    { V_BMP, "\001", "\"\\u0001\"", 0, 0 },
    { V_BMP, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_BMP, "/slash", "\"/slash\"", 0, 0 },
    { V_BMP, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_UNI, "hello", "\"hello\"", 0, 0 },
    { V_UNI, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_UNI, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_UNI, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_UNI, "\342\202\254", "\"\342\202\254\"", "\"\\u20ac\"", 0 },
    { V_UNI, "\360\237\230\200", "\"\360\237\230\200\"", "\"\\ud83d\\ude00\"", 0 },
    { V_UNI, "", "\"\"", 0, 0 },
    { V_UNI, "\001", "\"\\u0001\"", 0, 0 },
    { V_UNI, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_UNI, "/slash", "\"/slash\"", 0, 0 },
    { V_UNI, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_GEN, "hello", "\"hello\"", 0, 0 },
    { V_GEN, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_GEN, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_GEN, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_GEN, "", "\"\"", 0, 0 },
    { V_GEN, "\001", "\"\\u0001\"", 0, 0 },
    { V_GEN, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_GEN, "/slash", "\"/slash\"", 0, 0 },
    { V_GEN, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_GRAPH, "hello", "\"hello\"", 0, 0 },
    { V_GRAPH, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_GRAPH, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_GRAPH, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_GRAPH, "", "\"\"", 0, 0 },
    { V_GRAPH, "\001", "\"\\u0001\"", 0, 0 },
    { V_GRAPH, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_GRAPH, "/slash", "\"/slash\"", 0, 0 },
    { V_GRAPH, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_TELE, "hello", "\"hello\"", 0, 0 },
    { V_TELE, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_TELE, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_TELE, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_TELE, "", "\"\"", 0, 0 },
    { V_TELE, "\001", "\"\\u0001\"", 0, 0 },
    { V_TELE, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_TELE, "/slash", "\"/slash\"", 0, 0 },
    { V_TELE, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_OD, "hello", "\"hello\"", 0, 0 },
    { V_OD, "a\"b\\c", "\"a\\\"b\\\\c\"", 0, 0 },
    { V_OD, "tab\011here", "\"tab\\there\"", 0, 0 },
    { V_OD, "\303\251", "\"\303\251\"", "\"\\u00e9\"", 0 },
    { V_OD, "", "\"\"", 0, 0 },
    { V_OD, "\001", "\"\\u0001\"", 0, 0 },
    { V_OD, "line\012break", "\"line\\nbreak\"", 0, 0 },
    { V_OD, "/slash", "\"/slash\"", 0, 0 },
    { V_OD, "\037\177", "\"\\u001f\177\"", "\"\\u001f\\u007f\"", 0 },
    { V_T61, "hello", "\"hello\"", 0, 0 },
    { V_VIDEO, "hello", "\"hello\"", 0, 0 },
    { V_T61, "\303\251", "\"\303\251\"", 0, 0 },
    { V_VIDEO, "\303\251", "\"\303\251\"", 0, 0 },
    { V_T61, "a\"b", "\"a\\\"b\"", 0, 0 },
    { V_VIDEO, "a\"b", "\"a\\\"b\"", 0, 0 },
    { V_ANY, "", "\"\"", 0, 0 },
    { V_ANY, "3003020105", "\"3003020105\"", 0, 0 },
};

/* ENUMERATED { red(0), green(1), blue-ish(5) } */
static const asn_INTEGER_enum_map_t enum_v2e[] = {
    {0, 3, "red"}, {1, 5, "green"}, {5, 8, "blue-ish"}};
static const unsigned int enum_e2v[] = {2, 1, 0}; /* Sorted by identifier */
static const asn_INTEGER_specifics_t enum_specs = {
    enum_v2e, enum_e2v, 3, 0, 1, 0, 0};
static const asn_NativeReal_specifics_t float_specs = {sizeof(float)};
static const asn_jer_constraints_t fixed12 = {12, 0, 0};

static asn_TYPE_descriptor_t td_enum, td_nenum, td_nreal4, td_bitsf;

static void
init_tds(void) {
    td_enum = asn_DEF_ENUMERATED;
    td_enum.specifics = &enum_specs;
    td_nenum = asn_DEF_NativeEnumerated;
    td_nenum.specifics = &enum_specs;
    td_nreal4 = asn_DEF_NativeReal;
    td_nreal4.specifics = &float_specs;
    td_bitsf = asn_DEF_BIT_STRING;  /* BIT STRING (SIZE(12)) */
    td_bitsf.encoding_constraints.jer_constraints = &fixed12;
}

static const asn_TYPE_descriptor_t *
kind_td(int k) {
    switch(k) {
    case V_BOOL: return &asn_DEF_BOOLEAN;
    case V_NULL: return &asn_DEF_NULL;
    case V_INT: return &asn_DEF_INTEGER;
    case V_NINT: return &asn_DEF_NativeInteger;
    case V_ENUM: return &td_enum;
    case V_NENUM: return &td_nenum;
    case V_REAL: return &asn_DEF_REAL;
    case V_NREAL: return &asn_DEF_NativeReal;
    case V_NREAL4: return &td_nreal4;
    case V_OCT: return &asn_DEF_OCTET_STRING;
    case V_BITS: return &asn_DEF_BIT_STRING;
    case V_BITSF: return &td_bitsf;
    case V_OID: return &asn_DEF_OBJECT_IDENTIFIER;
    case V_ROID: return &asn_DEF_RELATIVE_OID;
    case V_UT: return &asn_DEF_UTCTime;
    case V_GT: return &asn_DEF_GeneralizedTime;
    case V_U8: return &asn_DEF_UTF8String;
    case V_IA5: return &asn_DEF_IA5String;
    case V_PRINT: return &asn_DEF_PrintableString;
    case V_VIS: return &asn_DEF_VisibleString;
    case V_NUM: return &asn_DEF_NumericString;
    case V_BMP: return &asn_DEF_BMPString;
    case V_UNI: return &asn_DEF_UniversalString;
    case V_GEN: return &asn_DEF_GeneralString;
    case V_GRAPH: return &asn_DEF_GraphicString;
    case V_TELE: return &asn_DEF_TeletexString;
    case V_T61: return &asn_DEF_T61String;
    case V_VIDEO: return &asn_DEF_VideotexString;
    case V_OD: return &asn_DEF_ObjectDescriptor;
    case V_ANY: return &asn_DEF_ANY;
    }
    assert(!"kind");
    return 0;
}

static void *
xcalloc(size_t n, size_t sz) {
    void *p = calloc(n, sz);
    assert(p);
    return p;
}

static int
hexval(int c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    assert(!"hex");
    return 0;
}

/* "DEAD" => bytes (with a courtesy NUL), *len = 2 */
static uint8_t *
hex_bytes(const char *h, size_t *len) {
    size_t n = strlen(h) / 2, i;
    uint8_t *b = (uint8_t *)xcalloc(n + 1, 1);
    for(i = 0; i < n; i++)
        b[i] = (uint8_t)(hexval(h[2 * i]) * 16 + hexval(h[2 * i + 1]));
    *len = n;
    return b;
}

/* Next code point of a UTF-8 string. */
static uint32_t
next_cp(const unsigned char **p) {
    const unsigned char *s = *p;
    uint32_t c = *s++;
    int extra = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : 0;
    if(extra) c &= (0x3f >> extra);
    while(extra--) c = (c << 6) | (*s++ & 0x3f);
    *p = s;
    return c;
}

/* The characters of a UTF-8 text as 1-byte (Latin-1), 2- or 4-byte units. */
static void
set_chars(OCTET_STRING_t *st, const char *utf8, int unit) {
    const unsigned char *p = (const unsigned char *)utf8;
    size_t n = strlen(utf8);
    uint8_t *b = (uint8_t *)xcalloc(n * 4 + 4, 1), *d = b;
    while(*p) {
        uint32_t c = next_cp(&p);
        int i;
        for(i = unit - 1; i >= 0; i--) *d++ = (uint8_t)(c >> (8 * i));
    }
    st->buf = b;
    st->size = (size_t)(d - b);
}

static void *
build(int k, const char *spec) {
    void *v;
    size_t len;
    switch(k) {
    case V_BOOL:
        v = xcalloc(1, sizeof(BOOLEAN_t));
        *(BOOLEAN_t *)v = (*spec == '1');
        return v;
    case V_NULL:
        return xcalloc(1, sizeof(NULL_t));
    case V_INT: {
        INTEGER_t *i = (INTEGER_t *)xcalloc(1, sizeof(*i));
        i->buf = hex_bytes(spec, &len);
        i->size = len;
        return i;
    }
    case V_NINT:
    case V_NENUM:
        v = xcalloc(1, sizeof(long));
        *(long *)v = strtol(spec, 0, 10);
        return v;
    case V_ENUM: {
        INTEGER_t *i = (INTEGER_t *)xcalloc(1, sizeof(*i));
        assert(asn_long2INTEGER(i, strtol(spec, 0, 10)) == 0);
        return i;
    }
    case V_REAL: {
        REAL_t *r = (REAL_t *)xcalloc(1, sizeof(*r));
        assert(asn_double2REAL(r, strtod(spec, 0)) == 0);
        return r;
    }
    case V_NREAL:
        v = xcalloc(1, sizeof(double));
        *(double *)v = strtod(spec, 0);
        return v;
    case V_NREAL4:
        v = xcalloc(1, sizeof(float));
        *(float *)v = (float)strtod(spec, 0);
        return v;
    case V_OCT: {
        OCTET_STRING_t *o = (OCTET_STRING_t *)xcalloc(1, sizeof(*o));
        o->buf = hex_bytes(spec, &len);
        o->size = len;
        return o;
    }
    case V_ANY: {
        ANY_t *a = (ANY_t *)xcalloc(1, sizeof(*a));
        a->buf = hex_bytes(spec, &len);
        a->size = (int)len;
        return a;
    }
    case V_BITS:
    case V_BITSF: {
        BIT_STRING_t *b = (BIT_STRING_t *)xcalloc(1, sizeof(*b));
        const char *slash = strchr(spec, '/');
        char hex[64];
        size_t bits = (size_t)atol(slash + 1);
        memcpy(hex, spec, (size_t)(slash - spec));
        hex[slash - spec] = 0;
        b->buf = hex_bytes(hex, &len);
        b->size = len;
        b->bits_unused = (int)(len * 8 - bits);
        return b;
    }
    case V_OID: {
        OBJECT_IDENTIFIER_t *o = (OBJECT_IDENTIFIER_t *)xcalloc(1, sizeof(*o));
        asn_oid_arc_t arcs[32];
        ssize_t n = OBJECT_IDENTIFIER_parse_arcs(spec, -1, arcs, 32, 0);
        assert(n > 0 && OBJECT_IDENTIFIER_set_arcs(o, arcs, (size_t)n) == 0);
        return o;
    }
    case V_ROID: {
        RELATIVE_OID_t *o = (RELATIVE_OID_t *)xcalloc(1, sizeof(*o));
        asn_oid_arc_t arcs[32];
        ssize_t n = OBJECT_IDENTIFIER_parse_arcs(spec, -1, arcs, 32, 0);
        assert(n > 0 && RELATIVE_OID_set_arcs(o, arcs, (size_t)n) == 0);
        return o;
    }
    case V_GEN: case V_GRAPH: case V_TELE: case V_T61: case V_VIDEO: {
        OCTET_STRING_t *o = (OCTET_STRING_t *)xcalloc(1, sizeof(*o));
        set_chars(o, spec, 1);  /* One octet per character (Latin-1) */
        return o;
    }
    case V_BMP: case V_UNI: {
        OCTET_STRING_t *o = (OCTET_STRING_t *)xcalloc(1, sizeof(*o));
        set_chars(o, spec, k == V_BMP ? 2 : 4);
        return o;
    }
    default: {  /* The octets are the text itself */
        OCTET_STRING_t *o = (OCTET_STRING_t *)xcalloc(1, sizeof(*o));
        o->size = strlen(spec);
        o->buf = (uint8_t *)xcalloc(o->size + 1, 1);
        memcpy(o->buf, spec, o->size);
        return o;
    }
    }
}

/* Encode; returns a malloc()ed NUL-terminated text, or NULL on failure. */
static char *
encode(const asn_TYPE_descriptor_t *td, const void *v,
       enum asn_transfer_syntax ats) {
    asn_encode_to_new_buffer_result_t r = asn_encode_to_new_buffer(0, ats, td, v);
    char *t;
    if(r.result.encoded < 0) {
        free(r.buffer);
        return 0;
    }
    t = (char *)xcalloc((size_t)r.result.encoded + 1, 1);
    memcpy(t, r.buffer, (size_t)r.result.encoded);
    free(r.buffer);
    return t;
}

static asn_dec_rval_t
decode(const asn_TYPE_descriptor_t *td, const char *text, void **out) {
    *out = 0;
    return asn_decode(0, ATS_JER, td, out, text, strlen(text));
}

static void
check_decodes_to(const struct vec *vv, const char *text, const void *expected,
                 const char *what) {
    const asn_TYPE_descriptor_t *td = kind_td(vv->kind);
    void *dec;
    asn_dec_rval_t r = decode(td, text, &dec);
    char *re;
    if(r.code != RC_OK) {
        printf("FAIL decoding %s [%s]: code %d\n", what, text, r.code);
        assert(r.code == RC_OK);
    }
    assert(dec);
    if(td->op->compare_struct(td, dec, expected) != 0) {
        printf("FAIL %s [%s]: decoded value differs\n", what, text);
        assert(0);
    }
    re = encode(td, dec, ATS_JER_MINIFIED);
    assert(re && strcmp(re, vv->ours) == 0);
    free(re);
    ASN_STRUCT_FREE(*td, dec);
}

static void
check_vector(const struct vec *vv) {
    const asn_TYPE_descriptor_t *td = kind_td(vv->kind);
    void *v = build(vv->kind, vv->spec);
    char *min = encode(td, v, ATS_JER_MINIFIED);
    char *pre = encode(td, v, ATS_JER);
    const char *want_pretty = vv->pretty ? vv->pretty : vv->ours;
    char padded[4096];

    printf("[%d] %s\n", vv->kind, vv->ours);
    assert(min && pre);
    if(strcmp(min, vv->ours)) {
        printf("FAIL minified: got [%s] want [%s]\n", min, vv->ours);
        assert(0);
    }
    if(strcmp(pre, want_pretty)) {
        printf("FAIL pretty: got [%s] want [%s]\n", pre, want_pretty);
        assert(0);
    }
    check_decodes_to(vv, min, v, "minified");
    check_decodes_to(vv, pre, v, "pretty");
    if(vv->alt) check_decodes_to(vv, vv->alt, v, "alt");
    assert(strlen(vv->ours) < 2000);
    snprintf(padded, sizeof(padded), " \t\r\n%s \n ", vv->ours);
    check_decodes_to(vv, padded, v, "padded");
    free(min);
    free(pre);
    ASN_STRUCT_FREE(*td, v);
}

/*
 * Inputs that are not what the encoder writes, but are valid JER:
 * white space, other spellings, escapes, surrogate pairs.
 */
static const struct {
    int kind;
    const char *input;
    const char *spec;   /* The value it decodes to (as in vecs[]) */
} accepts[] = {
    { V_BOOL, "  true\n", "1" },
    { V_BOOL, "\tfalse ", "0" },
    { V_NULL, " null ", "" },
    { V_INT, " -12 ", "F4" },
    { V_INT, "-0", "00" },
    { V_INT, "\n\t1000000 ", "0F4240" },
    { V_INT, "340282366920938463463374607431768211456", "0100000000000000000000000000000000" },
    { V_NINT, " 42 ", "42" },
    { V_NINT, "-1", "-1" },
    { V_ENUM, " \"green\" ", "1" },
    { V_NENUM, "\"blue\\u002dish\"", "5" },  /* Escaped identifier */
    { V_REAL, " 1.5e2 ", "0x1.2c00000000000p+7" },
    { V_REAL, "1E2", "0x1.9000000000000p+6" },
    { V_REAL, "0", "0x0.0p+0" },
    { V_REAL, "10", "0x1.4000000000000p+3" },
    { V_REAL, "-0.0", "-0x0.0p+0" },
    { V_NREAL, "2.5E-1", "0x1.0000000000000p-2" },
    { V_NREAL4, "0.100000001490116", "0x1.99999a0000000p-4" },
    { V_OCT, " \"deadbeef\" ", "DEADBEEF" },
    { V_OCT, "\"\"", "" },
    { V_BITS, "{\"length\":3,\"value\":\"A0\"}", "A0/3" },
    { V_BITS, " {\n  \"value\" : \"abc0\" ,\n  \"length\" :\t10 }\n", "ABC0/10" },
    { V_BITSF, " \"abc0\" ", "ABC0/12" },
    { V_OID, " \"1.2.840.113549\" ", "1.2.840.113549" },
    { V_ROID, " \"8571.3.2\" ", "8571.3.2" },
    { V_U8, " \"caf\\u00e9\" ", "caf\303\251" },
    { V_U8, "\"a\\/b\\\"c\\\\d\\b\\f\\n\\r\\t\"", "a/b\"c\\d\010\014\012\015\011" },
    { V_U8, "\"\\ud83d\\ude00\"", "\360\237\230\200" },
    { V_U8, "\"\\uD83D\\uDE00\"", "\360\237\230\200" },
    { V_U8, "\"\xe2\x82\xac\"", "\342\202\254" },       /* Raw UTF-8 */
    { V_IA5, "\"\\u0041\\u0042\"", "AB" },
    { V_BMP, "\"\\u00e9\\u20ac\"", "\303\251\342\202\254" },
    { V_BMP, "\"x\\\"y\"", "x\"y" },
    { V_UNI, "\"\\ud83d\\ude00\\u00e9\"", "\360\237\230\200\303\251" },
    { V_UNI, " \"\xf0\x9f\x98\x80\" ", "\360\237\230\200" },
    { V_GEN, "\"\\u00e9\"", "\303\251" },
    { V_UT, " \"170101120000Z\" ", "170101120000Z" },
    { V_ANY, "\"3003020105\"", "3003020105" },
};

/* Malformed or of the wrong JSON type: RC_FAIL, nothing left allocated. */
static const struct {
    int kind;
    const char *input;
} rejects[] = {
    { V_BOOL, "1" }, { V_BOOL, "True" }, { V_BOOL, "\"true\"" },
    { V_BOOL, "tru" }, { V_BOOL, "true false" }, { V_BOOL, "null" },
    { V_NULL, "nul" }, { V_NULL, "0" }, { V_NULL, "\"null\"" },
    { V_NULL, "false" },
    { V_INT, "1.5" }, { V_INT, "1.0" }, { V_INT, "1e3" }, { V_INT, "01" },
    { V_INT, "-" }, { V_INT, "+1" }, { V_INT, "\"5\"" }, { V_INT, "abc" },
    { V_INT, "0x10" }, { V_INT, "1 2" }, { V_INT, "true" },
    /* Out of range for the native type (long, 32 or 64 bits) */
    { V_NINT, "99999999999999999999" }, { V_NINT, "-99999999999999999999" },
    { V_NINT, "1.5" }, { V_NINT, "\"1\"" },
    { V_ENUM, "\"purple\"" }, { V_ENUM, "1" }, { V_ENUM, "\"Red\"" },
    { V_ENUM, "\"red" }, { V_ENUM, "red" }, { V_ENUM, "\"\"" },
    { V_NENUM, "\"purple\"" }, { V_NENUM, "5" },
    { V_REAL, "1." }, { V_REAL, ".5" }, { V_REAL, "\"inf\"" },
    { V_REAL, "\"INF\" 1" }, { V_REAL, "1e999" }, { V_REAL, "NaN" },
    { V_REAL, "\"1.5\"" }, { V_REAL, "-" }, { V_REAL, "00.5" },
    { V_REAL, "0x1p3" }, { V_REAL, "true" }, { V_REAL, "1e" },
    { V_NREAL, "\"-INF2\"" }, { V_NREAL4, "1e999" },
    { V_OCT, "\"ABC\"" }, { V_OCT, "\"GG\"" }, { V_OCT, "ABCD" },
    { V_OCT, "\"AB" }, { V_OCT, "\"AB CD\"" }, { V_OCT, "[\"AB\"]" },
    { V_OCT, "1234" }, { V_OCT, "\"AB\" \"CD\"" },
    { V_BITS, "\"A0\"" }, { V_BITS, "{\"value\":\"A0\"}" },
    { V_BITS, "{\"length\":3}" }, { V_BITS, "{\"value\":\"A0\",\"length\":9}" },
    { V_BITS, "{\"value\":\"A1\",\"length\":3}" },   /* Padding bits set */
    { V_BITS, "{\"value\":\"A0\",\"length\":-1}" },
    { V_BITS, "{\"value\":\"A0\",\"length\":3.0}" },
    { V_BITS, "{\"value\":\"A0\",\"length\":03}" },
    { V_BITS, "{\"value\":\"A0\",\"length\":\"3\"}" },
    { V_BITS, "{\"value\":\"A0\",\"value\":\"A0\"}" },
    { V_BITS, "{\"value\":\"A\",\"length\":3}" },
    { V_BITS, "{\"value\":\"ab c0\",\"length\":10}" },
    { V_BITS, "{\"value\":\"A0\",\"length\":3,\"extra\":1}" },
    { V_BITS, "{\"value\":\"A000\",\"length\":3}" },   /* Too many octets */
    { V_BITS, "true" }, { V_BITS, "{}" }, { V_BITS, "[]" },
    { V_BITSF, "\"ABC\"" }, { V_BITSF, "\"ABC1\"" },   /* Bits 13..16 set */
    { V_BITSF, "\"AB\"" }, { V_BITSF, "{\"value\":\"ABC0\",\"length\":12}" },
    { V_OID, "\"1.\"" }, { V_OID, "\"3.1\"" }, { V_OID, "\"1\"" },
    { V_OID, "\"1.40\"" }, { V_OID, "1.2.3" }, { V_OID, "\"1.2.a\"" },
    { V_OID, "\"{1 2 3}\"" }, { V_OID, "\" 1.2\"" }, { V_OID, "\"\"" },
    { V_OID, "\"1..2\"" }, { V_OID, "\"1.2" }, { V_OID, "[1,2]" },
    { V_ROID, "\"\"" }, { V_ROID, "\"1.\"" }, { V_ROID, "3.2" },
    { V_ROID, "\"a\"" },
    { V_U8, "\"abc" }, { V_U8, "abc" }, { V_U8, "123" }, { V_U8, "true" },
    { V_U8, "\"a\\qb\"" }, { V_U8, "\"\\ud800\"" }, { V_U8, "\"\\ude00\"" },
    { V_U8, "\"\\ud83d\\u0041\"" }, { V_U8, "\"\\u12\"" },
    { V_U8, "\"\\u12G4\"" }, { V_U8, "\"a\tb\"" } /* Raw TAB */,
    { V_U8, "\"abc\\\"" }, { V_U8, "\"abc\" x" }, { V_U8, "\"a\" \"b\"" },
    { V_U8, "\"\\" }, { V_U8, "null" }, { V_U8, "[\"a\"]" },
    { V_IA5, "\"x\\x\"" }, { V_PRINT, "'x'" }, { V_VIS, "\"x" },
    { V_NUM, "12" },
    { V_BMP, "\"\\ud83d\\ude00\"" },     /* Outside the BMP */
    { V_BMP, "\"\xf0\x9f\x98\x80\"" },
    { V_BMP, "\"\\ud83d\"" }, { V_BMP, "\"abc" }, { V_BMP, "5" },
    { V_UNI, "\"\\ud83d\"" }, { V_UNI, "\"abc" }, { V_UNI, "false" },
    { V_UNI, "\"\xc3\"" },               /* Malformed UTF-8 */
    { V_GEN, "\"\\u20ac\"" },            /* Not a Latin-1 character */
    { V_GEN, "\"\xe2\x82\xac\"" }, { V_GEN, "\"abc" }, { V_GEN, "7" },
    { V_UT, "170101120000Z" }, { V_GT, "\"2017" },
    { V_ANY, "\"3\"" }, { V_ANY, "3003" },
};

static void
check_extra(void) {
    size_t i;
    for(i = 0; i < sizeof(accepts) / sizeof(accepts[0]); i++) {
        void *v;
        const asn_TYPE_descriptor_t *td = kind_td(accepts[i].kind);
        void *dec;
        asn_dec_rval_t r = decode(td, accepts[i].input, &dec);
        char *re, *re2;

        printf("accept [%s]\n", accepts[i].input);
        assert(r.code == RC_OK && dec);
        v = build(accepts[i].kind, accepts[i].spec);
        assert(td->op->compare_struct(td, dec, v) == 0);
        /* And it encodes to the canonical text, which decodes the same */
        re = encode(td, dec, ATS_JER_MINIFIED);
        assert(re);
        re2 = encode(td, v, ATS_JER_MINIFIED);
        assert(re2 && strcmp(re, re2) == 0);
        free(re);
        free(re2);
        ASN_STRUCT_FREE(*td, v);
        ASN_STRUCT_FREE(*td, dec);
    }
}

static void
check_rejects(void) {
    size_t i;
    for(i = 0; i < sizeof(rejects) / sizeof(rejects[0]); i++) {
        const asn_TYPE_descriptor_t *td = kind_td(rejects[i].kind);
        void *dec;
        asn_dec_rval_t r = decode(td, rejects[i].input, &dec);
        printf("reject [%s]\n", rejects[i].input);
        if(r.code != RC_FAIL) {
            printf("FAIL: kind %d code %d\n", rejects[i].kind, r.code);
            assert(r.code == RC_FAIL);
        }
        assert(r.consumed == 0);
        if(dec) ASN_STRUCT_FREE(*td, dec);  /* Freed by the caller: no leak */
    }
}

/* Input that may still become valid: RC_WMORE, nothing consumed. */
static void
check_incomplete(void) {
    static const struct { int kind; const char *input; } inc[] = {
        { V_BOOL, "" }, { V_BOOL, "  \n" }, { V_INT, "" },
        { V_BITS, "" }, { V_BITS, "{" }, { V_BITS, "{\"value\":\"A0\"," },
        { V_BITS, "{\"value\":\"A0\",\"length\":3" },
        { V_BITS, "{\"value\":\"A0\",\"len" }, { V_BITSF, "\"AB" },
    };
    size_t i;
    for(i = 0; i < sizeof(inc) / sizeof(inc[0]); i++) {
        const asn_TYPE_descriptor_t *td = kind_td(inc[i].kind);
        void *dec;
        asn_dec_rval_t r = decode(td, inc[i].input, &dec);
        printf("incomplete [%s]\n", inc[i].input);
        assert(r.code == RC_WMORE && r.consumed == 0);
        if(dec) ASN_STRUCT_FREE(*td, dec);
    }
}

/* A decode into an existing structure replaces the value (no leak). */
static void
check_redecode(void) {
    const asn_TYPE_descriptor_t *td = &asn_DEF_UTF8String;
    void *dec = 0;
    asn_dec_rval_t r;
    const char *a = "\"first\"", *b = "\"second one\"";
    r = asn_decode(0, ATS_JER, td, &dec, a, strlen(a));
    assert(r.code == RC_OK);
    r = asn_decode(0, ATS_JER, td, &dec, b, strlen(b));
    assert(r.code == RC_OK);
    assert(((UTF8String_t *)dec)->size == 10
           && memcmp(((UTF8String_t *)dec)->buf, "second one", 10) == 0);
    /* A failing decode leaves the previous value intact */
    r = asn_decode(0, ATS_JER, td, &dec, "\"bad\\q\"", 7);
    assert(r.code == RC_FAIL);
    assert(((UTF8String_t *)dec)->size == 10
           && memcmp(((UTF8String_t *)dec)->buf, "second one", 10) == 0);
    ASN_STRUCT_FREE(*td, dec);
}

/* Encoding refuses values that are not valid. */
static void
check_encode_failures(void) {
    OCTET_STRING_t os = {0, 0, {0, 0, 0, 0}};
    BIT_STRING_t bs;
    ENUMERATED_t en;
    long unknown = 7;
    UTCTime_t ut;
    OCTET_STRING_t bmp;

    memset(&bs, 0, sizeof(bs));
    memset(&en, 0, sizeof(en));
    memset(&ut, 0, sizeof(ut));
    memset(&bmp, 0, sizeof(bmp));

    /* Unknown ENUMERATED value */
    assert(encode(&td_nenum, &unknown, ATS_JER) == 0);
    assert(asn_long2INTEGER(&en, 7) == 0);
    assert(encode(&td_enum, &en, ATS_JER) == 0);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &en);

    /* A NULL buffer with a size */
    os.size = 3;
    assert(encode(&asn_DEF_OCTET_STRING, &os, ATS_JER) == 0);

    /* BIT STRING with bits set in the unused part: written as 0 bits;
     * then a fixed size mismatch */
    bs.buf = (uint8_t *)"\xbf";
    bs.size = 1;
    bs.bits_unused = 3;
    {
        char *t = encode(&asn_DEF_BIT_STRING, &bs, ATS_JER);
        assert(t);
        assert(strstr(t, "\"B8\""));
        free(t);
    }
    bs.buf = (uint8_t *)"\xa0";
    {
        char *t = encode(&asn_DEF_BIT_STRING, &bs, ATS_JER);
        assert(t);
        free(t);
    }
    assert(encode(&td_bitsf, &bs, ATS_JER) == 0);

    /* Invalid time */
    ut.buf = (uint8_t *)"not a time";
    ut.size = 10;
    assert(encode(&asn_DEF_UTCTime, &ut, ATS_JER) == 0);

    /* Odd number of octets in a BMPString */
    bmp.buf = (uint8_t *)"\0a\0";
    bmp.size = 3;
    assert(encode(&asn_DEF_BMPString, &bmp, ATS_JER) == 0);
}

int
main(void) {
    size_t i;

    setvbuf(stdout, 0, _IOLBF, 0);  /* Keep the output when an assert fires */
    init_tds();
    for(i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++)
        check_vector(&vecs[i]);
    check_extra();
    check_rejects();
    check_incomplete();
    check_redecode();
    check_encode_failures();
    printf("%d vectors, %d accepted inputs, %d rejected inputs\n",
           (int)(sizeof(vecs) / sizeof(vecs[0])),
           (int)(sizeof(accepts) / sizeof(accepts[0])),
           (int)(sizeof(rejects) / sizeof(rejects[0])));
    return 0;
}
