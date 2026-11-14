// Restricted character string types and the two time types
// (tests/e2e/strings.asn). Copied into the generated module by
// tests/run-e2e.sh together with default_test.go (the converter helpers) and
// seqof_test.go (siCase / siMk / siList).
//
// Every type maps to a Go string. Eleven restricted string types and both time
// types carry the C buffer's bytes unchanged; BMPString (UCS-2) and
// UniversalString (UCS-4) are converted to and from UTF-8 by the generated Go
// glue. Constraint checking (SIZE, FROM, NumericString digits, time syntax)
// stays in the C runtime.
//
// Per value: Go APER == the C converter's APER of the same value written as
// XER; Go's decode gives the value back; the converter's XER of the Go APER is
// the given XER and re-encodes to the same APER. The shapes covered per type:
//
//	top level     all 15 types          (stCases, "top" rows)
//	member        every type, mandatory (Rec)
//	OPTIONAL      every type            (Rec, "...o" members)
//	SEQUENCE OF   every type            (the *List types, top level; ListHolder
//	                                     for BMP / Universal / IA5 as members)
//	CHOICE alt    every type            (Alt)
//	reference     BMP / Universal / IA5 behind a named type, mandatory and
//	                                    OPTIONAL (Rec, Alt, BmpRefList)
//	extension     BMP / Universal / IA5 as extension additions (Ext)
//
// The allocation-fault sweep over the same values is in faults_test.go.
package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
	st "asn1cgo.test/go/strs"
)

// stCase is a siCase plus, for a composite value, XER fragments the
// converter's XER must contain (xer is "" when the whole document is not
// spelled out).
type stCase struct {
	siCase
	has []string
}

func stMk[T any](name, pdu, xer string, v *T, dec func([]byte) (*T, error), has ...string) stCase {
	return stCase{siCase: siMk(name, pdu, xer, v, dec), has: has}
}

var stGap = regexp.MustCompile(`>\s+<`)

// stNorm drops the whitespace the converter puts between elements (not the
// whitespace inside text).
func stNorm(b []byte) string {
	return strings.TrimSpace(stGap.ReplaceAllString(string(b), "><"))
}

func stp[T any](v T) *T { return &v }

// stHex is how the C runtime writes GeneralString, GraphicString,
// TeletexString, T61String and VideotexString in XER: it does not decode their
// character sets, so it prints (and reads) the bytes as hex.
func stHex(s string) string {
	var o []string
	for i := 0; i < len(s); i++ {
		o = append(o, fmt.Sprintf("%02X", s[i]))
	}
	return strings.Join(o, " ")
}

func stEl(tag, text string) string { return "<" + tag + ">" + text + "</" + tag + ">" }

func stList(pdu, tag string, vs ...string) string {
	var o []string
	for _, v := range vs {
		o = append(o, stEl(tag, v))
	}
	return siList(pdu, o...)
}

const (
	stMulti = "héllo ✓" // 2- and 3-byte UTF-8, all in the BMP
	stClef  = "𝄞"       // U+1D11E, outside the BMP
)

// stFullRec is a Rec with every OPTIONAL member present (opt) or absent.
func stFullRec(opt bool) *st.Rec {
	r := &st.Rec{
		Ia5: "ia5", Num: "12 34", Vis: "vis", Utf: stMulti, Bmp: stMulti,
		Univ: stMulti + stClef, Genl: "genl", Grap: "grap", Tele: "tele",
		T61: "t61", Video: "video", Obj: "obj", Utc: "250102030405Z",
		Gt: "20250102030405.5Z", Bmpref: "bmpref", Univref: stClef,
		Ia5ref: "ia5ref", Flag: true,
	}
	if opt {
		r.Ia5o = stp("ia5o")
		r.Numo = stp("987")
		r.Viso = stp("viso")
		r.Utfo = stp(stMulti)
		r.Bmpo = stp(stMulti)
		r.Univo = stp(stClef + "a")
		r.Genlo = stp("genlo")
		r.Grapo = stp("grapo")
		r.Teleo = stp("teleo")
		r.T61o = stp("t61o")
		r.Videoo = stp("videoo")
		r.Objo = stp("objo")
		r.Utco = stp("251231235959Z")
		r.Gto = stp("20251231235959Z")
		r.Bmprefo = stp(st.BmpNamed("bmprefo✓"))
		r.Univrefo = stp(st.UnivNamed(stClef + stClef))
		r.Ia5refo = stp(st.IA5Named("ia5re"))
	}
	return r
}

func stCases() []stCase {
	var cs []stCase
	add := func(c stCase) { cs = append(cs, c) }

	// ---- top level, one row per type (and per interesting value) ----
	add(stMk("ia5top", "IA5Top", stEl("IA5Top", "ab12"), stp(st.IA5Top("ab12")), st.DecodeIA5Top))
	add(stMk("ia5top-min", "IA5Top", stEl("IA5Top", "z9"), stp(st.IA5Top("z9")), st.DecodeIA5Top))
	add(stMk("ia5top-max", "IA5Top", stEl("IA5Top", "abcdef"), stp(st.IA5Top("abcdef")), st.DecodeIA5Top))
	add(stMk("numtop", "NumTop", stEl("NumTop", "123 45"), stp(st.NumTop("123 45")), st.DecodeNumTop))
	add(stMk("numtop-1", "NumTop", stEl("NumTop", "0"), stp(st.NumTop("0")), st.DecodeNumTop))
	add(stMk("vistop", "VisTop", stEl("VisTop", "Hello, World"), stp(st.VisTop("Hello, World")), st.DecodeVisTop))
	add(stMk("vistop-escape", "VisTop", stEl("VisTop", "a&lt;b&amp;c&gt;d"), stp(st.VisTop("a<b&c>d")), st.DecodeVisTop))
	add(stMk("vistop-empty", "VisTop", stEl("VisTop", ""), stp(st.VisTop("")), st.DecodeVisTop))
	add(stMk("utftop", "UtfTop", stEl("UtfTop", stMulti), stp(st.UtfTop(stMulti)), st.DecodeUtfTop))
	add(stMk("utftop-empty", "UtfTop", stEl("UtfTop", ""), stp(st.UtfTop("")), st.DecodeUtfTop))
	add(stMk("utftop-clef", "UtfTop", stEl("UtfTop", stClef), stp(st.UtfTop(stClef)), st.DecodeUtfTop))
	add(stMk("bmptop", "BmpTop", stEl("BmpTop", stMulti), stp(st.BmpTop(stMulti)), st.DecodeBmpTop))
	add(stMk("bmptop-1", "BmpTop", stEl("BmpTop", "é"), stp(st.BmpTop("é")), st.DecodeBmpTop))
	add(stMk("bmptop-max", "BmpTop", stEl("BmpTop", strings.Repeat("✓", 16)), stp(st.BmpTop(strings.Repeat("✓", 16))), st.DecodeBmpTop))
	add(stMk("bmpfree-empty", "BmpFree", stEl("BmpFree", ""), stp(st.BmpFree("")), st.DecodeBmpFree))
	add(stMk("bmpfree", "BmpFree", stEl("BmpFree", stMulti), stp(st.BmpFree(stMulti)), st.DecodeBmpFree))
	add(stMk("bmpfree-130", "BmpFree", stEl("BmpFree", strings.Repeat("x", 130)), stp(st.BmpFree(strings.Repeat("x", 130))), st.DecodeBmpFree))
	// U+FFFF is a BMP code point; a genuine U+FFFD must not be mistaken for
	// the replacement the Go runtime yields for invalid UTF-8.
	add(stMk("bmpfree-ffff", "BmpFree", "", stp(st.BmpFree("a\uffffb")), st.DecodeBmpFree))
	add(stMk("bmpfree-fffd", "BmpFree", "", stp(st.BmpFree("\ufffd")), st.DecodeBmpFree))
	add(stMk("univtop", "UnivTop", stEl("UnivTop", stClef), stp(st.UnivTop(stClef)), st.DecodeUnivTop))
	add(stMk("univtop-mixed", "UnivTop", stEl("UnivTop", "a"+stClef+"é"), stp(st.UnivTop("a"+stClef+"é")), st.DecodeUnivTop))
	add(stMk("univtop-max", "UnivTop", stEl("UnivTop", strings.Repeat(stClef, 8)), stp(st.UnivTop(strings.Repeat(stClef, 8))), st.DecodeUnivTop))
	add(stMk("univfree-empty", "UnivFree", stEl("UnivFree", ""), stp(st.UnivFree("")), st.DecodeUnivFree))
	add(stMk("univfree", "UnivFree", stEl("UnivFree", stMulti+stClef), stp(st.UnivFree(stMulti+stClef)), st.DecodeUnivFree))
	add(stMk("univfree-fffd", "UnivFree", "", stp(st.UnivFree("\ufffd")), st.DecodeUnivFree))
	add(stMk("genltop", "GenlTop", stEl("GenlTop", stHex("general")), stp(st.GenlTop("general")), st.DecodeGenlTop))
	add(stMk("graptop", "GrapTop", stEl("GrapTop", stHex("graphic")), stp(st.GrapTop("graphic")), st.DecodeGrapTop))
	add(stMk("teletop", "TeleTop", stEl("TeleTop", stHex("teletex")), stp(st.TeleTop("teletex")), st.DecodeTeleTop))
	add(stMk("t61top", "T61Top", stEl("T61Top", stHex("t61")), stp(st.T61Top("t61")), st.DecodeT61Top))
	add(stMk("videotop", "VideoTop", stEl("VideoTop", stHex("videotex")), stp(st.VideoTop("videotex")), st.DecodeVideoTop))
	add(stMk("objtop", "ObjTop", stEl("ObjTop", "descriptor"), stp(st.ObjTop("descriptor")), st.DecodeObjTop))
	add(stMk("utctop", "UtcTop", stEl("UtcTop", "250102030405Z"), stp(st.UtcTop("250102030405Z")), st.DecodeUtcTop))
	// Not normalised: the text the caller gave is the text on the wire.
	add(stMk("utctop-nosec", "UtcTop", stEl("UtcTop", "2501020304Z"), stp(st.UtcTop("2501020304Z")), st.DecodeUtcTop))
	add(stMk("utctop-offset", "UtcTop", stEl("UtcTop", "250102030405+0100"), stp(st.UtcTop("250102030405+0100")), st.DecodeUtcTop))
	add(stMk("gttop", "GtTop", stEl("GtTop", "20250102030405.5Z"), stp(st.GtTop("20250102030405.5Z")), st.DecodeGtTop))
	add(stMk("gttop-whole", "GtTop", stEl("GtTop", "20250102030405Z"), stp(st.GtTop("20250102030405Z")), st.DecodeGtTop))
	add(stMk("gttop-offset", "GtTop", stEl("GtTop", "20250102030405-0500"), stp(st.GtTop("20250102030405-0500")), st.DecodeGtTop))

	// ---- SEQUENCE OF element, top level ----
	add(stMk("ia5list", "Ia5List", stList("Ia5List", "IA5String", "ab", "cd1", "wxyz"), stp(st.Ia5List{"ab", "cd1", "wxyz"}), st.DecodeIa5List))
	add(stMk("ia5list-empty", "Ia5List", siList("Ia5List"), stp(st.Ia5List(nil)), st.DecodeIa5List))
	add(stMk("numlist", "NumList", stList("NumList", "NumericString", "12", "3456"), stp(st.NumList{"12", "3456"}), st.DecodeNumList))
	add(stMk("vislist", "VisList", stList("VisList", "VisibleString", "a", "b b"), stp(st.VisList{"a", "b b"}), st.DecodeVisList))
	add(stMk("utflist", "UtfList", stList("UtfList", "UTF8String", stMulti, ""), stp(st.UtfList{stMulti, ""}), st.DecodeUtfList))
	add(stMk("bmplist", "BmpList", stList("BmpList", "BMPString", stMulti, "", "é"), stp(st.BmpList{stMulti, "", "é"}), st.DecodeBmpList))
	add(stMk("bmplist-empty", "BmpList", siList("BmpList"), stp(st.BmpList(nil)), st.DecodeBmpList))
	add(stMk("univlist", "UnivList", stList("UnivList", "UniversalString", stClef, "a", ""), stp(st.UnivList{stClef, "a", ""}), st.DecodeUnivList))
	add(stMk("genllist", "GenlList", stList("GenlList", "GeneralString", stHex("g1"), stHex("g2")), stp(st.GenlList{"g1", "g2"}), st.DecodeGenlList))
	add(stMk("graplist", "GrapList", stList("GrapList", "GraphicString", stHex("g1")), stp(st.GrapList{"g1"}), st.DecodeGrapList))
	add(stMk("telelist", "TeleList", stList("TeleList", "TeletexString", stHex("t1"), stHex("t2")), stp(st.TeleList{"t1", "t2"}), st.DecodeTeleList))
	add(stMk("t61list", "T61List", stList("T61List", "T61String", stHex("t1")), stp(st.T61List{"t1"}), st.DecodeT61List))
	add(stMk("videolist", "VideoList", stList("VideoList", "VideotexString", stHex("v1"), stHex("v2")), stp(st.VideoList{"v1", "v2"}), st.DecodeVideoList))
	add(stMk("objlist", "ObjList", stList("ObjList", "ObjectDescriptor", "o1"), stp(st.ObjList{"o1"}), st.DecodeObjList))
	add(stMk("utclist", "UtcList", stList("UtcList", "UTCTime", "250102030405Z", "251231235959Z"), stp(st.UtcList{"250102030405Z", "251231235959Z"}), st.DecodeUtcList))
	add(stMk("gtlist", "GtList", stList("GtList", "GeneralizedTime", "20250102030405.5Z"), stp(st.GtList{"20250102030405.5Z"}), st.DecodeGtList))
	add(stMk("bmpreflist", "BmpRefList", stList("BmpRefList", "BmpNamed", "é", stMulti), stp(st.BmpRefList{"é", stMulti}), st.DecodeBmpRefList))

	// ---- SEQUENCE OF element as a member / OPTIONAL member ----
	add(stMk("listholder-min", "ListHolder", "", &st.ListHolder{Flag: true}, st.DecodeListHolder, "<flag><true/></flag>"))
	add(stMk("listholder-full", "ListHolder", "",
		&st.ListHolder{
			Bmps:  st.ListHolderBmps{stMulti, "é"},
			Univs: &st.ListHolderUnivs{stClef, "b"},
			Ia5s:  &st.ListHolderIa5s{"x", "yz"},
			Flag:  false,
		}, st.DecodeListHolder,
		"<BMPString>"+stMulti+"</BMPString>", "<UniversalString>"+stClef+"</UniversalString>", "<IA5String>yz</IA5String>"))

	// ---- members, OPTIONAL members, references ----
	add(stMk("rec-required", "Rec", "", stFullRec(false), st.DecodeRec,
		"<ia5>ia5</ia5>", "<num>12 34</num>", "<vis>vis</vis>", "<utf>"+stMulti+"</utf>",
		"<bmp>"+stMulti+"</bmp>", "<univ>"+stMulti+stClef+"</univ>",
		"<genl>"+stHex("genl")+"</genl>", "<grap>"+stHex("grap")+"</grap>", "<tele>"+stHex("tele")+"</tele>", "<t61>"+stHex("t61")+"</t61>",
		"<video>"+stHex("video")+"</video>", "<obj>obj</obj>", "<utc>250102030405Z</utc>",
		"<gt>20250102030405.5Z</gt>", "<bmpref>bmpref</bmpref>", "<univref>"+stClef+"</univref>",
		"<ia5ref>ia5ref</ia5ref>"))
	add(stMk("rec-optional", "Rec", "", stFullRec(true), st.DecodeRec,
		"<ia5o>ia5o</ia5o>", "<numo>987</numo>", "<viso>viso</viso>", "<utfo>"+stMulti+"</utfo>",
		"<bmpo>"+stMulti+"</bmpo>", "<univo>"+stClef+"a</univo>",
		"<genlo>"+stHex("genlo")+"</genlo>", "<grapo>"+stHex("grapo")+"</grapo>", "<teleo>"+stHex("teleo")+"</teleo>", "<t61o>"+stHex("t61o")+"</t61o>",
		"<videoo>"+stHex("videoo")+"</videoo>", "<objo>objo</objo>", "<utco>251231235959Z</utco>",
		"<gto>20251231235959Z</gto>", "<bmprefo>bmprefo✓</bmprefo>", "<univrefo>"+stClef+stClef+"</univrefo>",
		"<ia5refo>ia5re</ia5refo>"))
	rec := stFullRec(true)
	rec.Bmp, rec.Univ, rec.Bmpref, rec.Univref = "", "", "x", "y"
	rec.Bmpo, rec.Univo = stp(""), stp("")
	add(stMk("rec-empty-strings", "Rec", "", rec, st.DecodeRec, "<bmpo></bmpo>", "<univo></univo>"))

	// ---- CHOICE alternatives ----
	alt := func(name string, a *st.Alt, has string) {
		add(stMk("alt-"+name, "Alt", "", a, st.DecodeAlt, has))
	}
	alt("ia5", &st.Alt{Present: st.AltPrIa5, Ia5: stp("ia5")}, "<ia5>ia5</ia5>")
	alt("num", &st.Alt{Present: st.AltPrNum, Num: stp("1 2")}, "<num>1 2</num>")
	alt("vis", &st.Alt{Present: st.AltPrVis, Vis: stp("vis")}, "<vis>vis</vis>")
	alt("utf", &st.Alt{Present: st.AltPrUtf, Utf: stp(stMulti)}, "<utf>"+stMulti+"</utf>")
	alt("bmp", &st.Alt{Present: st.AltPrBmp, Bmp: stp(stMulti)}, "<bmp>"+stMulti+"</bmp>")
	alt("bmp-empty", &st.Alt{Present: st.AltPrBmp, Bmp: stp("")}, "<bmp></bmp>")
	alt("univ", &st.Alt{Present: st.AltPrUniv, Univ: stp(stClef)}, "<univ>"+stClef+"</univ>")
	alt("genl", &st.Alt{Present: st.AltPrGenl, Genl: stp("genl")}, "<genl>"+stHex("genl")+"</genl>")
	alt("grap", &st.Alt{Present: st.AltPrGrap, Grap: stp("grap")}, "<grap>"+stHex("grap")+"</grap>")
	alt("tele", &st.Alt{Present: st.AltPrTele, Tele: stp("tele")}, "<tele>"+stHex("tele")+"</tele>")
	alt("t61", &st.Alt{Present: st.AltPrT61, T61: stp("t61")}, "<t61>"+stHex("t61")+"</t61>")
	alt("video", &st.Alt{Present: st.AltPrVideo, Video: stp("video")}, "<video>"+stHex("video")+"</video>")
	alt("obj", &st.Alt{Present: st.AltPrObj, Obj: stp("obj")}, "<obj>obj</obj>")
	alt("utc", &st.Alt{Present: st.AltPrUtc, Utc: stp("250102030405Z")}, "<utc>250102030405Z</utc>")
	alt("gt", &st.Alt{Present: st.AltPrGt, Gt: stp("20250102030405.5Z")}, "<gt>20250102030405.5Z</gt>")
	alt("bmpref", &st.Alt{Present: st.AltPrBmpref, Bmpref: stp(st.BmpNamed(stMulti))}, "<bmpref>"+stMulti+"</bmpref>")
	alt("univref", &st.Alt{Present: st.AltPrUnivref, Univref: stp(st.UnivNamed(stClef))}, "<univref>"+stClef+"</univref>")

	// ---- DEFAULT (single-byte string types) ----
	add(stMk("dflt-defaults", "Dflt", "", &st.Dflt{Ia5: st.DfltIa5Default, Vis: st.DfltVisDefault, Num: st.DfltNumDefault, Flag: true}, st.DecodeDflt,
		"<ia5>hi</ia5>", "<vis>vv</vis>", "<num>42</num>"))
	add(stMk("dflt-other", "Dflt", "", &st.Dflt{Ia5: "yo", Vis: "ww", Num: "7", Flag: false}, st.DecodeDflt,
		"<ia5>yo</ia5>", "<vis>ww</vis>", "<num>7</num>"))

	// ---- DEFAULT BMPString / UniversalString (stored as UCS-2 / UCS-4) ----
	// All members equal to their DEFAULT: omitted from the encoding, so the
	// APER is the C encoding of the value with them absent.
	add(stMk("dfltw-defaults", "DfltW", "",
		&st.DfltW{Bmp: st.DfltWBmpDefault, Bmpu: st.DfltWBmpuDefault, Univ: st.DfltWUnivDefault, Univu: st.DfltWUnivuDefault, Flag: true}, st.DecodeDfltW,
		"<bmp>hi</bmp>", "<bmpu>é€</bmpu>", "<univ>hi</univ>", "<univu>😀</univu>"))
	add(stMk("dfltw-other", "DfltW", "", &st.DfltW{Bmp: "yo", Bmpu: "€é", Univ: "x", Univu: "😁", Flag: false}, st.DecodeDfltW,
		"<bmp>yo</bmp>", "<bmpu>€é</bmpu>", "<univ>x</univ>", "<univu>😁</univu>"))
	add(stMk("dfltw-mixed", "DfltW", "", &st.DfltW{Bmp: "hi", Bmpu: "é", Univ: "hi", Univu: "😀", Flag: true}, st.DecodeDfltW,
		"<bmpu>é</bmpu>"))

	// ---- extension additions ----
	add(stMk("ext-all", "Ext", "", &st.Ext{A: 3, Bmp: stp(stMulti), Univo: stp(stClef), Ia5: stp("ext")}, st.DecodeExt,
		"<bmp>"+stMulti+"</bmp>", "<univo>"+stClef+"</univo>", "<ia5>ext</ia5>"))
	add(stMk("ext-no-opt", "Ext", "", &st.Ext{A: 3, Bmp: stp(""), Ia5: stp("e")}, st.DecodeExt, "<bmp></bmp>"))

	// ---- PrintableString, empty and non-empty (KNOWN-ISSUES.md #11) ----
	add(stMk("prttop-empty", "PrtTop", stEl("PrtTop", ""), stp(st.PrtTop("")), st.DecodePrtTop))
	add(stMk("prttop", "PrtTop", stEl("PrtTop", "Hello 1"), stp(st.PrtTop("Hello 1")), st.DecodePrtTop))
	add(stMk("prtsmall-empty", "PrtSmall", stEl("PrtSmall", ""), stp(st.PrtSmall("")), st.DecodePrtSmall))
	add(stMk("prtsmall", "PrtSmall", stEl("PrtSmall", "abcd"), stp(st.PrtSmall("abcd")), st.DecodePrtSmall))
	add(stMk("prtone", "PrtOne", stEl("PrtOne", "a"), stp(st.PrtOne("a")), st.DecodePrtOne))
	add(stMk("prtrec-empty", "PrtRec", "", &st.PrtRec{Flag: true}, st.DecodePrtRec,
		"<p></p>", "<s></s>", "<ref></ref>", "<refs></refs>"))
	add(stMk("prtrec-opt-empty", "PrtRec", "", &st.PrtRec{Po: stp(""), So: stp(""), Refo: stp(st.PrtNamed("")), Flag: false}, st.DecodePrtRec,
		"<po></po>", "<so></so>", "<refo></refo>"))
	add(stMk("prtrec-full", "PrtRec", "", &st.PrtRec{P: "p 1", Po: stp("po"), S: "s", So: stp("so"), Ref: "ref", Refo: stp(st.PrtNamed("refo")), Refs: "rs", Flag: true}, st.DecodePrtRec,
		"<p>p 1</p>", "<po>po</po>", "<s>s</s>", "<so>so</so>", "<ref>ref</ref>", "<refo>refo</refo>", "<refs>rs</refs>"))
	prtAlt := func(name string, a *st.PrtAlt, has string) {
		add(stMk("prtalt-"+name, "PrtAlt", "", a, st.DecodePrtAlt, has))
	}
	prtAlt("p-empty", &st.PrtAlt{Present: st.PrtAltPrP, P: stp("")}, "<p></p>")
	prtAlt("s-empty", &st.PrtAlt{Present: st.PrtAltPrS, S: stp("")}, "<s></s>")
	prtAlt("ref-empty", &st.PrtAlt{Present: st.PrtAltPrRef, Ref: stp(st.PrtNamed(""))}, "<ref></ref>")
	prtAlt("refs-empty", &st.PrtAlt{Present: st.PrtAltPrRefs, Refs: stp(st.PrtNamedSmall(""))}, "<refs></refs>")
	prtAlt("p", &st.PrtAlt{Present: st.PrtAltPrP, P: stp("abc")}, "<p>abc</p>")
	add(stMk("prtlist", "PrtList", stList("PrtList", "PrintableString", "ab", "", "c"), stp(st.PrtList{"ab", "", "c"}), st.DecodePrtList))
	add(stMk("prtlist-empty-elem", "PrtList", stList("PrtList", "PrintableString", ""), stp(st.PrtList{""}), st.DecodePrtList))
	add(stMk("prtsmalllist", "PrtSmallList", stList("PrtSmallList", "PrintableString", "", "abcd"), stp(st.PrtSmallList{"", "abcd"}), st.DecodePrtSmallList))
	add(stMk("prtreflist", "PrtRefList", stList("PrtRefList", "PrtNamed", "", "x"), stp(st.PrtRefList{"", "x"}), st.DecodePrtRefList))
	add(stMk("prtholder", "PrtHolder", "", &st.PrtHolder{L: st.PrtHolderL{"", "a"}, Lo: &st.PrtHolderLo{""}, Flag: true}, st.DecodePrtHolder,
		"<PrintableString></PrintableString>", "<PrintableString>a</PrintableString>"))

	return cs
}

func TestStringsRoundTrip(t *testing.T) {
	for _, c := range stCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
		balanced(t, c.name)
	}
}

func TestStringsCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range stCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if c.xer != "" {
			if ref, ok := siConv(t, bin, c.siCase, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
				t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
			}
		}
		if re, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if c.xer != "" && siSelfClose(stNorm(xer)) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, stNorm(xer), c.xer)
		}
		for _, h := range c.has {
			if !strings.Contains(siSelfClose(stNorm(xer)), siSelfClose(h)) {
				t.Errorf("%s: C XER lacks %s:\n%s", c.name, h, xer)
			}
		}
		if re, ok := siConv(t, bin, c.siCase, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

type stEnc interface{ Encode() ([]byte, error) }

// stBadCase: a value that must come back from Encode as an error. glue marks
// the errors raised by the generated Go glue itself (BMPString /
// UniversalString content that has no UCS-2 / UCS-4 form); every other error
// comes from the C runtime's constraint check.
type stBadCase struct {
	name string
	v    stEnc
	glue string // substring of the glue's message, "" for a C constraint error
}

func stBadCases() []stBadCase {
	var bs []stBadCase
	add := func(name string, v stEnc, glue string) { bs = append(bs, stBadCase{name, v, glue}) }

	// IA5String (SIZE(2..6) ^ FROM("a".."z" | "0".."9")): SIZE and FROM
	add("ia5-too-short", stp(st.IA5Top("a")), "")
	add("ia5-too-long", stp(st.IA5Top("abcdefg")), "")
	add("ia5-empty", stp(st.IA5Top("")), "")
	add("ia5-from-upper", stp(st.IA5Top("AB12")), "")
	add("ia5-from-punct", stp(st.IA5Top("ab-12")), "")
	add("ia5-8bit", stp(st.IA5Top("ab\x80c")), "")
	// NumericString: digits and space only
	add("num-letter", stp(st.NumTop("12a")), "")
	add("num-tab", stp(st.NumTop("1\t2")), "")
	add("num-too-long", stp(st.NumTop("1234567")), "")
	add("num-empty", stp(st.NumTop("")), "")
	// VisibleString: printable ASCII only
	add("vis-control", stp(st.VisTop("a\x01b")), "")
	add("vis-8bit", stp(st.VisTop("h\xc3\xa9")), "")
	// BMPString: SIZE, and what has no UCS-2 form (rejected by the glue)
	add("bmp-empty-size", stp(st.BmpTop("")), "")
	add("bmp-too-long", stp(st.BmpTop(strings.Repeat("a", 17))), "")
	add("bmp-non-bmp", stp(st.BmpFree("a"+stClef)), "Basic Multilingual Plane")
	add("bmp-non-bmp-only", stp(st.BmpFree(stClef)), "Basic Multilingual Plane")
	add("bmp-max-rune", stp(st.BmpFree("\U0010ffff")), "Basic Multilingual Plane")
	add("bmp-bad-utf8", stp(st.BmpFree("a\xffb")), "not valid UTF-8")
	add("bmp-truncated-utf8", stp(st.BmpFree("a\xc3")), "not valid UTF-8")
	add("bmp-surrogate-utf8", stp(st.BmpFree("a\xed\xa0\x80")), "not valid UTF-8")
	add("bmp-in-list", stp(st.BmpList{"ok", stClef}), "Basic Multilingual Plane")
	add("bmp-in-member", &st.Ext{A: 1, Bmp: stp(stClef), Ia5: stp("x")}, "Basic Multilingual Plane")
	add("bmp-in-alt", &st.Alt{Present: st.AltPrBmp, Bmp: stp(stClef)}, "Basic Multilingual Plane")
	add("bmp-in-ref-alt", &st.Alt{Present: st.AltPrBmpref, Bmpref: stp(st.BmpNamed(stClef))}, "Basic Multilingual Plane")
	bad := stFullRec(true)
	bad.Bmpo = stp("x" + stClef)
	add("bmp-in-optional", bad, "Basic Multilingual Plane")
	bad = stFullRec(true)
	bad.Bmprefo = stp(st.BmpNamed("\xff"))
	add("bmp-in-optional-ref", bad, "not valid UTF-8")
	bad = stFullRec(false)
	bad.Bmpref = st.BmpNamed(stClef)
	add("bmp-in-ref", bad, "Basic Multilingual Plane")
	// UniversalString: every scalar value is representable; invalid UTF-8 is not
	add("univ-bad-utf8", stp(st.UnivFree("a\xffb")), "not valid UTF-8")
	add("univ-surrogate-utf8", stp(st.UnivFree("\xed\xa0\x80")), "not valid UTF-8")
	add("univ-too-long", stp(st.UnivTop(strings.Repeat("a", 9))), "")
	add("univ-empty-size", stp(st.UnivTop("")), "")
	add("univ-in-list", stp(st.UnivList{"ok", "\xc0\x80"}), "not valid UTF-8")
	add("univ-in-alt", &st.Alt{Present: st.AltPrUniv, Univ: stp("\xf8")}, "not valid UTF-8")
	bad = stFullRec(true)
	bad.Univo = stp("\xe2\x82")
	add("univ-in-optional", bad, "not valid UTF-8")
	// PrintableString (SIZE(1..4)): the empty value is still a constraint error
	add("prt-one-empty", stp(st.PrtOne("")), "")
	add("prt-one-too-long", stp(st.PrtOne("abcde")), "")
	add("prt-top-bad-char", stp(st.PrtTop("a@b")), "")
	add("prt-small-too-long", stp(st.PrtSmall("abcde")), "")
	// time types: the C runtime checks the syntax (UTCTime_constraint /
	// GeneralizedTime_constraint -> asn_UT2time / asn_GT2time)
	for _, v := range []string{"garbage", "", "250102", "251302030405Z", "250132030405Z", "25010203040Z", "2501020304059Z", "２５０１０２０３０４０５Z"} {
		add("utc-"+v, stp(st.UtcTop(v)), "")
	}
	for _, v := range []string{"garbage", "", "2025", "20251302030405Z"} {
		add("gt-"+v, stp(st.GtTop(v)), "")
	}
	add("utc-in-list", stp(st.UtcList{"250102030405Z", "nope"}), "")
	add("gt-in-alt", &st.Alt{Present: st.AltPrGt, Gt: stp("nope")}, "")
	// the other string types in composites
	add("list-ia5-elem", stp(st.Ia5List{"ok", ""}), "")
	add("list-num-elem", stp(st.NumList{"1", "x"}), "")
	add("list-too-long", stp(st.Ia5List{"a", "b", "c", "d"}), "")
	add("alt-num", &st.Alt{Present: st.AltPrNum, Num: stp("1x")}, "")
	add("alt-ia5-size", &st.Alt{Present: st.AltPrIa5, Ia5: stp("123456789")}, "")
	add("dflt-ia5", &st.Dflt{Ia5: "\xff", Vis: "v", Num: "1"}, "")
	return bs
}

func TestStringsEncodeErrors(t *testing.T) {
	for _, c := range stBadCases() {
		var out []byte
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: Encode panicked: %v", c.name, r)
				}
			}()
			out, err = c.v.Encode()
		}()
		if err == nil {
			t.Errorf("%s: Encode accepted the value: % x", c.name, out)
			continue
		}
		if out != nil {
			t.Errorf("%s: Encode returned bytes with an error", c.name)
		}
		var re *rt.Error
		if !errors.As(err, &re) {
			t.Errorf("%s: err = %T %v, want *rt.Error", c.name, err, err)
			continue
		}
		// Both the glue's own checks and the C runtime's report a value that
		// does not fit the type as a constraint violation.
		if c.glue != "" || !strings.HasPrefix(c.name, "list-") {
			if !errors.Is(err, rt.ErrConstraint) {
				t.Errorf("%s: err = %v, want rt.ErrConstraint", c.name, err)
			}
		} else if !errors.Is(err, rt.ErrConstraint) && !errors.Is(err, rt.ErrEncode) {
			// a SEQUENCE OF over its SIZE bound is an aper encode failure
			t.Errorf("%s: err = %v, want rt.ErrConstraint or rt.ErrEncode", c.name, err)
		}
		if c.glue != "" && !strings.Contains(re.Message, c.glue) {
			t.Errorf("%s: message %q lacks %q", c.name, re.Message, c.glue)
		}
		balanced(t, c.name)
	}
}

// Hand-made APER whose C decode succeeds but whose BMPString / UniversalString
// content is not valid Unicode: the Go decode must say so, not substitute
// U+FFFD. (An odd UCS-2 length cannot be built this way: APER counts
// characters. strs_internal_test.go feeds such buffers to the read helpers
// directly.)
func TestStringsDecodeErrors(t *testing.T) {
	bmp := func(b ...byte) []byte { return append([]byte{byte(len(b) / 2)}, b...) }
	univ := func(b ...byte) []byte { return append([]byte{byte(len(b) / 4)}, b...) }
	cases := []struct {
		name string
		wire []byte
		dec  func([]byte) error
		want string
	}{
		{"bmp-high-surrogate", bmp(0xD8, 0x00), func(b []byte) error { _, e := st.DecodeBmpFree(b); return e }, "surrogate"},
		{"bmp-low-surrogate", bmp(0x00, 0x61, 0xDF, 0xFF), func(b []byte) error { _, e := st.DecodeBmpFree(b); return e }, "surrogate"},
		{"bmp-surrogate-pair", bmp(0xD8, 0x34, 0xDD, 0x1E), func(b []byte) error { _, e := st.DecodeBmpFree(b); return e }, "surrogate"},
		{"univ-surrogate", univ(0x00, 0x00, 0xD8, 0x00), func(b []byte) error { _, e := st.DecodeUnivFree(b); return e }, "not a Unicode scalar"},
		{"univ-above-10ffff", univ(0x00, 0x11, 0x00, 0x00), func(b []byte) error { _, e := st.DecodeUnivFree(b); return e }, "not a Unicode scalar"},
		{"univ-ffffffff", univ(0xFF, 0xFF, 0xFF, 0xFF), func(b []byte) error { _, e := st.DecodeUnivFree(b); return e }, "not a Unicode scalar"},
		{"univ-second-bad", univ(0x00, 0x00, 0x00, 0x61, 0x80, 0x00, 0x00, 0x00), func(b []byte) error { _, e := st.DecodeUnivFree(b); return e }, "not a Unicode scalar"},
	}
	for _, c := range cases {
		err := c.dec(c.wire)
		var re *rt.Error
		if !errors.As(err, &re) || !errors.Is(err, rt.ErrDecode) {
			t.Errorf("%s: Decode % x err = %v, want an rt.ErrDecode *rt.Error", c.name, c.wire, err)
			continue
		}
		if !strings.Contains(re.Message, c.want) {
			t.Errorf("%s: message %q lacks %q", c.name, re.Message, c.want)
		}
		balanced(t, c.name)
	}
	// The same bytes with a valid scalar decode fine (the cases above fail
	// because of the content, not the framing).
	if v, err := st.DecodeBmpFree(append([]byte{1}, 0x26, 0x3A)); err != nil || *v != "☺" {
		t.Errorf("valid BMP: %v %v", v, err)
	}
	if v, err := st.DecodeUnivFree([]byte{1, 0x00, 0x01, 0xD1, 0x1E}); err != nil || *v != stClef {
		t.Errorf("valid Universal: %v %v", v, err)
	}
}

// What the C runtime does with a time string it does not understand, and what
// it lets through unchanged. The Go side neither parses nor normalises.
func TestStringsTimeSyntax(t *testing.T) {
	for _, ok := range []string{
		"250102030405Z", "2501020304Z", "250102030405", "250102030405+0100", "250102030405-0530",
	} {
		w, err := stp(st.UtcTop(ok)).Encode()
		if err != nil {
			t.Errorf("UTCTime %q rejected: %v", ok, err)
			continue
		}
		if v, err := st.DecodeUtcTop(w); err != nil || string(*v) != ok {
			t.Errorf("UTCTime %q round trip = %v, %v", ok, v, err)
		}
	}
	for _, ok := range []string{
		"20250102030405Z", "20250102030405.5Z", "20250102030405.123456Z", "20250102030405+0100",
		"2025010203Z", "202501020304Z", "20250102030405",
	} {
		w, err := stp(st.GtTop(ok)).Encode()
		if err != nil {
			t.Errorf("GeneralizedTime %q rejected: %v", ok, err)
			continue
		}
		if v, err := st.DecodeGtTop(w); err != nil || string(*v) != ok {
			t.Errorf("GeneralizedTime %q round trip = %v, %v", ok, v, err)
		}
	}
}

// The C time check (asn_UT2time / asn_GT2time) parses a prefix and ignores
// what follows it, so trailing junk after a well-formed time is accepted. The
// Go side does not add a stricter check of its own: the text goes through
// unchanged. (Documented behavior of the C runtime, not a feature.)
func TestStringsTimeTrailingJunk(t *testing.T) {
	for _, v := range []string{"250102030405ZZ", "250102030405Zjunk"} {
		w, err := stp(st.UtcTop(v)).Encode()
		if err != nil {
			t.Errorf("UTCTime %q: %v (the C check accepts trailing junk)", v, err)
			continue
		}
		if got, err := st.DecodeUtcTop(w); err != nil || string(*got) != v {
			t.Errorf("UTCTime %q round trip = %v, %v", v, got, err)
		}
	}
	for _, v := range []string{"20250102030405.Z", "20250102030405.5ZZ", "20250102030405,5"} {
		w, err := stp(st.GtTop(v)).Encode()
		if err != nil {
			t.Errorf("GeneralizedTime %q: %v", v, err)
			continue
		}
		if got, err := st.DecodeGtTop(w); err != nil || string(*got) != v {
			t.Errorf("GeneralizedTime %q round trip = %v, %v", v, got, err)
		}
	}
}

// A wrong value in a composite names no panic and leaves no arena behind, and
// a nil pointer for a mandatory-looking CHOICE alternative is the usual
// ErrChoiceBad, not a crash in the string glue.
func TestStringsChoiceNil(t *testing.T) {
	for _, a := range []*st.Alt{
		{Present: st.AltPrBmp},
		{Present: st.AltPrUniv},
		{Present: st.AltPrBmpref},
		{Present: st.AltPrIa5},
	} {
		_, err := a.Encode()
		wantErr(t, fmt.Sprintf("Present=%d, alt nil", a.Present), err, rt.ErrChoiceBad)
	}
}

func TestStringsDeepEqualDecoded(t *testing.T) {
	// A decoded value shares no memory with the C buffer: it survives the
	// arena being freed (the strings are Go copies).
	w, err := stFullRec(true).Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.DecodeRec(w)
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.DecodeRec(w)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, stFullRec(true)) {
		t.Errorf("decoded values differ:\n%+v\n%+v", a, b)
	}
	balanced(t, "rec")
}

// An all-default DfltW omits every DEFAULT member (a 4-bit preamble of zeros
// plus the BOOLEAN), and a decoder fills the absent members with the DEFAULT
// as real UCS-2 / UCS-4 text.
func TestStringsBmpDefaultOmitted(t *testing.T) {
	v := &st.DfltW{Bmp: "hi", Bmpu: "é€", Univ: "hi", Univu: "😀", Flag: true}
	b, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x08}; !bytes.Equal(b, want) {
		t.Fatalf("APER of the all-default value = % x, want % x", b, want)
	}
	// The C converter agrees: XER with the members absent -> the same APER.
	bin := converter(t)
	c := siMk("dfltw-absent", "DfltW", "", v, st.DecodeDfltW)
	if ref, ok := siConv(t, bin, c, []byte("<DfltW><flag><true/></flag></DfltW>"), "-ixer", "-oaper"); ok && !bytes.Equal(ref, b) {
		t.Errorf("C APER of the absent-members XER % x != Go % x", ref, b)
	}
	got, err := st.DecodeDfltW(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bmp != "hi" || got.Bmpu != "é€" || got.Univ != "hi" || got.Univu != "😀" || !got.Flag {
		t.Fatalf("decoded %+v", got)
	}
}
