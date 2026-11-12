// Inline (anonymous) SEQUENCE / CHOICE types as SEQUENCE members and as CHOICE
// alternatives (tests/e2e/inlconstr.asn). Copied into the generated module by
// tests/run-e2e.sh together with seqofinline_test.go (the siCase helpers) and
// default_test.go (the converter helpers).
//
// Every shape of the module has a value per interesting state: required and
// OPTIONAL inline SEQUENCE members (absent and present), inner OPTIONAL and
// extension members, two levels of nesting, an inline SEQUENCE / CHOICE as the
// first, middle and last CHOICE alternative (every alternative selected, and
// every alternative of the inner CHOICEs), and inline SEQUENCE / CHOICE types
// inside an inline SEQUENCE OF element. Per case:
//
//   - Go APER == the C converter's APER of the same value written as XER;
//   - Go's decode of that APER gives the value back (reflect.DeepEqual);
//   - the converter's XER of the Go APER is the given XER, and re-encodes to
//     the same APER.
//
// The allocation-fault sweep over the same values is in faults_test.go.
package e2e

import (
	"bytes"
	"strings"
	"testing"

	ic "asn1cgo.test/go/inlconstr"
)

func icCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
	i64 := func(v int64) *int64 { return &v }
	bp := siPtr[bool]
	bl := siBool
	// wrap(pdu, inner) = <pdu>inner</pdu>
	wrap := func(pdu string, inner ...string) string {
		return "<" + pdu + ">" + strings.Join(inner, "") + "</" + pdu + ">"
	}
	el := func(name string, inner ...string) string { return wrap(name, inner...) }
	x := func(v int64) string { return el("x", itoa(v)) }

	// ---- inline SEQUENCE as a SEQUENCE member ----
	req := func(name string, v *ic.MemReq, a, b string) {
		add(siMk(name, "MemReq", wrap("MemReq", a, b), v, ic.DecodeMemReq))
	}
	req("memreq-0", &ic.MemReq{A: ic.MemReqA{X: 0}, B: false}, el("a", x(0)), el("b", bl(false)))
	req("memreq-3", &ic.MemReq{A: ic.MemReqA{X: 3}, B: true}, el("a", x(3)), el("b", bl(true)))

	opt := func(name string, v *ic.MemOpt, a, b string) {
		add(siMk(name, "MemOpt", wrap("MemOpt", a, b), v, ic.DecodeMemOpt))
	}
	opt("memopt-absent", &ic.MemOpt{B: true}, "", el("b", bl(true)))
	opt("memopt-present", &ic.MemOpt{A: &ic.MemOptA{X: 2}, B: false}, el("a", x(2)), el("b", bl(false)))

	// own OPTIONAL and extension members
	ext := func(name string, v *ic.MemExt, a, b, c string) {
		add(siMk(name, "MemExt", wrap("MemExt", a, b, c), v, ic.DecodeMemExt))
	}
	ext("memext-min", &ic.MemExt{A: ic.MemExtA{X: 1}, C: true},
		el("a", x(1)), "", el("c", bl(true)))
	ext("memext-y", &ic.MemExt{A: ic.MemExtA{X: 2, Y: bp(true)}, C: false},
		el("a", x(2), el("y", bl(true))), "", el("c", bl(false)))
	ext("memext-z", &ic.MemExt{A: ic.MemExtA{X: 3, Z: i64(5)}, C: true},
		el("a", x(3), el("z", "5")), "", el("c", bl(true)))
	ext("memext-yz", &ic.MemExt{A: ic.MemExtA{X: 0, Y: bp(false), Z: i64(7)}, C: false},
		el("a", x(0), el("y", bl(false)), el("z", "7")), "", el("c", bl(false)))
	ext("memext-b", &ic.MemExt{A: ic.MemExtA{X: 1}, B: &ic.MemExtB{Q: true}, C: true},
		el("a", x(1)), el("b", el("q", bl(true))), el("c", bl(true)))
	ext("memext-bp", &ic.MemExt{A: ic.MemExtA{X: 1, Z: i64(1)}, B: &ic.MemExtB{P: &[]byte{0xAB, 0x01}, Q: false}, C: false},
		el("a", x(1), el("z", "1")), el("b", el("p", "AB01"), el("q", bl(false))), el("c", bl(false)))

	// nested two levels deep
	deep := func(name string, v *ic.MemDeep, a, e string) {
		add(siMk(name, "MemDeep", wrap("MemDeep", a, e), v, ic.DecodeMemDeep))
	}
	deep("memdeep-min", &ic.MemDeep{A: ic.MemDeepA{B: ic.MemDeepAB{X: 1}}, E: true},
		el("a", el("b", x(1))), el("e", bl(true)))
	deep("memdeep-y", &ic.MemDeep{A: ic.MemDeepA{B: ic.MemDeepAB{X: 2, Y: bp(false)}}, E: false},
		el("a", el("b", x(2), el("y", bl(false)))), el("e", bl(false)))
	deep("memdeep-c", &ic.MemDeep{A: ic.MemDeepA{B: ic.MemDeepAB{X: 0}, C: &ic.MemDeepAC{}}, E: true},
		el("a", el("b", x(0)), el("c")), el("e", bl(true)))
	deep("memdeep-cd", &ic.MemDeep{A: ic.MemDeepA{B: ic.MemDeepAB{X: 3, Y: bp(true)}, C: &ic.MemDeepAC{D: &ic.MemDeepACD{Z: true}}}, E: false},
		el("a", el("b", x(3), el("y", bl(true))), el("c", el("d", el("z", bl(true))))), el("e", bl(false)))

	// an inline SEQUENCE holding an inline CHOICE, and an OPTIONAL inline CHOICE
	// holding an inline SEQUENCE alt
	mix := func(name string, v *ic.MemMix, a, e string) {
		add(siMk(name, "MemMix", wrap("MemMix", a, e), v, ic.DecodeMemMix))
	}
	mix("memmix-x", &ic.MemMix{A: ic.MemMixA{C: ic.MemMixAC{Present: ic.MemMixACPrX, X: i64(2)}, D: true}},
		el("a", el("c", x(2)), el("d", bl(true))), "")
	mix("memmix-y-es", &ic.MemMix{
		A: ic.MemMixA{C: ic.MemMixAC{Present: ic.MemMixACPrY, Y: bp(true)}, D: false},
		E: &ic.MemMixE{Present: ic.MemMixEPrS, S: &ic.MemMixES{T: 3}}},
		el("a", el("c", el("y", bl(true))), el("d", bl(false))), el("e", el("s", el("t", "3"))))
	mix("memmix-x-eu", &ic.MemMix{
		A: ic.MemMixA{C: ic.MemMixAC{Present: ic.MemMixACPrX, X: i64(0)}, D: true},
		E: &ic.MemMixE{Present: ic.MemMixEPrU, U: bp(false)}},
		el("a", el("c", x(0)), el("d", bl(true))), el("e", el("u", bl(false))))

	// ---- inline SEQUENCE as a CHOICE alt ----
	as := func(name string, v *ic.AltSeq, inner string) {
		add(siMk(name, "AltSeq", wrap("AltSeq", inner), v, ic.DecodeAltSeq))
	}
	as("altseq-a", &ic.AltSeq{Present: ic.AltSeqPrA, A: &ic.AltSeqA{X: 3}}, el("a", x(3)))
	as("altseq-b", &ic.AltSeq{Present: ic.AltSeqPrB, B: bp(true)}, el("b", bl(true)))

	am := func(name string, v *ic.AltSeqMid, inner string) {
		add(siMk(name, "AltSeqMid", wrap("AltSeqMid", inner), v, ic.DecodeAltSeqMid))
	}
	am("altseqmid-b", &ic.AltSeqMid{Present: ic.AltSeqMidPrB, B: bp(false)}, el("b", bl(false)))
	am("altseqmid-a", &ic.AltSeqMid{Present: ic.AltSeqMidPrA, A: &ic.AltSeqMidA{X: 1}}, el("a", x(1)))
	am("altseqmid-a-y", &ic.AltSeqMid{Present: ic.AltSeqMidPrA, A: &ic.AltSeqMidA{X: 2, Y: bp(true)}}, el("a", x(2), el("y", bl(true))))
	am("altseqmid-c", &ic.AltSeqMid{Present: ic.AltSeqMidPrC, C: i64(3)}, el("c", "3"))

	al := func(name string, v *ic.AltSeqLast, inner string) {
		add(siMk(name, "AltSeqLast", wrap("AltSeqLast", inner), v, ic.DecodeAltSeqLast))
	}
	al("altseqlast-b", &ic.AltSeqLast{Present: ic.AltSeqLastPrB, B: bp(true)}, el("b", bl(true)))
	al("altseqlast-a", &ic.AltSeqLast{Present: ic.AltSeqLastPrA, A: &ic.AltSeqLastA{Y: []byte{0x0F}}}, el("a", el("y", "0F")))
	al("altseqlast-a-x", &ic.AltSeqLast{Present: ic.AltSeqLastPrA, A: &ic.AltSeqLastA{X: i64(2), Y: []byte{1, 2}}}, el("a", x(2), el("y", "0102")))

	// ---- inline CHOICE as a CHOICE alt: first, middle, last ----
	cf := func(name string, v *ic.AltChoiceFirst, inner string) {
		add(siMk(name, "AltChoiceFirst", wrap("AltChoiceFirst", inner), v, ic.DecodeAltChoiceFirst))
	}
	cf("altchoicefirst-ax", &ic.AltChoiceFirst{Present: ic.AltChoiceFirstPrA, A: &ic.AltChoiceFirstA{Present: ic.AltChoiceFirstAPrX, X: i64(1)}}, el("a", x(1)))
	cf("altchoicefirst-ay", &ic.AltChoiceFirst{Present: ic.AltChoiceFirstPrA, A: &ic.AltChoiceFirstA{Present: ic.AltChoiceFirstAPrY, Y: bp(true)}}, el("a", el("y", bl(true))))
	cf("altchoicefirst-b", &ic.AltChoiceFirst{Present: ic.AltChoiceFirstPrB, B: bp(false)}, el("b", bl(false)))

	cm := func(name string, v *ic.AltChoiceMid, inner string) {
		add(siMk(name, "AltChoiceMid", wrap("AltChoiceMid", inner), v, ic.DecodeAltChoiceMid))
	}
	cm("altchoicemid-b", &ic.AltChoiceMid{Present: ic.AltChoiceMidPrB, B: bp(true)}, el("b", bl(true)))
	cm("altchoicemid-ax", &ic.AltChoiceMid{Present: ic.AltChoiceMidPrA, A: &ic.AltChoiceMidA{Present: ic.AltChoiceMidAPrX, X: i64(3)}}, el("a", x(3)))
	cm("altchoicemid-ay", &ic.AltChoiceMid{Present: ic.AltChoiceMidPrA, A: &ic.AltChoiceMidA{Present: ic.AltChoiceMidAPrY, Y: bp(false)}}, el("a", el("y", bl(false))))
	cm("altchoicemid-c", &ic.AltChoiceMid{Present: ic.AltChoiceMidPrC, C: i64(2)}, el("c", "2"))

	cl := func(name string, v *ic.AltChoiceLast, inner string) {
		add(siMk(name, "AltChoiceLast", wrap("AltChoiceLast", inner), v, ic.DecodeAltChoiceLast))
	}
	cl("altchoicelast-b", &ic.AltChoiceLast{Present: ic.AltChoiceLastPrB, B: bp(false)}, el("b", bl(false)))
	cl("altchoicelast-ax", &ic.AltChoiceLast{Present: ic.AltChoiceLastPrA, A: &ic.AltChoiceLastA{Present: ic.AltChoiceLastAPrX, X: i64(0)}}, el("a", x(0)))
	cl("altchoicelast-ay", &ic.AltChoiceLast{Present: ic.AltChoiceLastPrA, A: &ic.AltChoiceLastA{Present: ic.AltChoiceLastAPrY, Y: bp(true)}}, el("a", el("y", bl(true))))

	// nested two levels deep
	cd := func(name string, v *ic.AltChoiceDeep, inner string) {
		add(siMk(name, "AltChoiceDeep", wrap("AltChoiceDeep", inner), v, ic.DecodeAltChoiceDeep))
	}
	cd("altchoicedeep-abx", &ic.AltChoiceDeep{Present: ic.AltChoiceDeepPrA, A: &ic.AltChoiceDeepA{
		Present: ic.AltChoiceDeepAPrB, B: &ic.AltChoiceDeepAB{Present: ic.AltChoiceDeepABPrX, X: i64(2)}}},
		el("a", el("b", x(2))))
	cd("altchoicedeep-aby", &ic.AltChoiceDeep{Present: ic.AltChoiceDeepPrA, A: &ic.AltChoiceDeepA{
		Present: ic.AltChoiceDeepAPrB, B: &ic.AltChoiceDeepAB{Present: ic.AltChoiceDeepABPrY, Y: bp(true)}}},
		el("a", el("b", el("y", bl(true)))))
	cd("altchoicedeep-ac", &ic.AltChoiceDeep{Present: ic.AltChoiceDeepPrA, A: &ic.AltChoiceDeepA{
		Present: ic.AltChoiceDeepAPrC, C: bp(false)}},
		el("a", el("c", bl(false))))
	cd("altchoicedeep-d", &ic.AltChoiceDeep{Present: ic.AltChoiceDeepPrD, D: bp(true)}, el("d", bl(true)))

	cs2 := func(name string, v *ic.AltChoiceDeepSeq, inner string) {
		add(siMk(name, "AltChoiceDeepSeq", wrap("AltChoiceDeepSeq", inner), v, ic.DecodeAltChoiceDeepSeq))
	}
	cs2("altchoicedeepseq-ab", &ic.AltChoiceDeepSeq{Present: ic.AltChoiceDeepSeqPrA, A: &ic.AltChoiceDeepSeqA{
		Present: ic.AltChoiceDeepSeqAPrB, B: &ic.AltChoiceDeepSeqAB{X: 1}}},
		el("a", el("b", x(1))))
	cs2("altchoicedeepseq-ab-y", &ic.AltChoiceDeepSeq{Present: ic.AltChoiceDeepSeqPrA, A: &ic.AltChoiceDeepSeqA{
		Present: ic.AltChoiceDeepSeqAPrB, B: &ic.AltChoiceDeepSeqAB{X: 3, Y: bp(true)}}},
		el("a", el("b", x(3), el("y", bl(true)))))
	cs2("altchoicedeepseq-ac", &ic.AltChoiceDeepSeq{Present: ic.AltChoiceDeepSeqPrA, A: &ic.AltChoiceDeepSeqA{
		Present: ic.AltChoiceDeepSeqAPrC, C: bp(true)}},
		el("a", el("c", bl(true))))
	cs2("altchoicedeepseq-def", &ic.AltChoiceDeepSeq{Present: ic.AltChoiceDeepSeqPrD, D: &ic.AltChoiceDeepSeqD{
		E: ic.AltChoiceDeepSeqDE{Present: ic.AltChoiceDeepSeqDEPrF, F: bp(false)}}},
		el("d", el("e", el("f", bl(false)))))
	cs2("altchoicedeepseq-deg", &ic.AltChoiceDeepSeq{Present: ic.AltChoiceDeepSeqPrD, D: &ic.AltChoiceDeepSeqD{
		E: ic.AltChoiceDeepSeqDE{Present: ic.AltChoiceDeepSeqDEPrG, G: i64(3)}}},
		el("d", el("e", el("g", "3"))))

	// ---- inline SEQUENCE / CHOICE inside an inline SEQUENCE OF element ----
	sq := func(name string, v *ic.SofSeq, a, b string) {
		add(siMk(name, "SofSeq", wrap("SofSeq", a, b), v, ic.DecodeSofSeq))
	}
	sq("sofseq-empty", &ic.SofSeq{}, el("a"), "")
	sq("sofseq-a2", &ic.SofSeq{A: ic.SofSeqA{
		{X: 1, Y: ic.SofSeqAMemberY{Z: true}}, {X: 3, Y: ic.SofSeqAMemberY{Z: false}}}},
		el("a",
			"<SEQUENCE>"+x(1)+el("y", el("z", bl(true)))+"</SEQUENCE>",
			"<SEQUENCE>"+x(3)+el("y", el("z", bl(false)))+"</SEQUENCE>"), "")
	sq("sofseq-b-empty", &ic.SofSeq{B: new(ic.SofSeqB)}, el("a"), el("b"))
	sq("sofseq-b3", &ic.SofSeq{
		A: ic.SofSeqA{{X: 0, Y: ic.SofSeqAMemberY{Z: true}}},
		B: &ic.SofSeqB{
			{Present: ic.SofSeqBMemberPrX, X: i64(2)},
			{Present: ic.SofSeqBMemberPrY, Y: &ic.SofSeqBMemberY{Z: true}},
			{Present: ic.SofSeqBMemberPrX, X: i64(0)}}},
		el("a", "<SEQUENCE>"+x(0)+el("y", el("z", bl(true)))+"</SEQUENCE>"),
		el("b", x(2), el("y", el("z", bl(true))), x(0)))

	st := func(name string, v *ic.SofSeqTop, elems ...string) {
		add(siMk(name, "SofSeqTop", siList("SofSeqTop", elems...), v, ic.DecodeSofSeqTop))
	}
	st("sofseqtop-empty", new(ic.SofSeqTop))
	st("sofseqtop-2", &ic.SofSeqTop{
		{X: ic.SofSeqTopMemberX{Present: ic.SofSeqTopMemberXPrP, P: bp(true)}},
		{X: ic.SofSeqTopMemberX{Present: ic.SofSeqTopMemberXPrQ, Q: &ic.SofSeqTopMemberXQ{R: 2}}, Y: &ic.SofSeqTopMemberY{Z: false}}},
		"<SEQUENCE>"+el("x", el("p", bl(true)))+"</SEQUENCE>",
		"<SEQUENCE>"+el("x", el("q", el("r", "2")))+el("y", el("z", bl(false)))+"</SEQUENCE>")

	ct := func(name string, v *ic.SofChoiceTop, elems ...string) {
		add(siMk(name, "SofChoiceTop", siList("SofChoiceTop", elems...), v, ic.DecodeSofChoiceTop))
	}
	ct("sofchoicetop-empty", new(ic.SofChoiceTop))
	ct("sofchoicetop-3", &ic.SofChoiceTop{
		{Present: ic.SofChoiceTopMemberPrX, X: &ic.SofChoiceTopMemberX{Z: true}},
		{Present: ic.SofChoiceTopMemberPrY, Y: &ic.SofChoiceTopMemberY{Present: ic.SofChoiceTopMemberYPrP, P: bp(false)}},
		{Present: ic.SofChoiceTopMemberPrY, Y: &ic.SofChoiceTopMemberY{Present: ic.SofChoiceTopMemberYPrQ, Q: i64(3)}}},
		el("x", el("z", bl(true))), el("y", el("p", bl(false))), el("y", el("q", "3")))

	sa := func(name string, v *ic.SofAlt, inner string) {
		add(siMk(name, "SofAlt", wrap("SofAlt", inner), v, ic.DecodeSofAlt))
	}
	sa("sofalt-a1", &ic.SofAlt{Present: ic.SofAltPrA, A: &ic.SofAltA{B: ic.SofAltAB{2}}},
		el("a", el("b", "<INTEGER>2</INTEGER>")))
	sa("sofalt-a4", &ic.SofAlt{Present: ic.SofAltPrA, A: &ic.SofAltA{B: ic.SofAltAB{0, 1, 2, 3}}},
		el("a", el("b", "<INTEGER>0</INTEGER><INTEGER>1</INTEGER><INTEGER>2</INTEGER><INTEGER>3</INTEGER>")))
	sa("sofalt-c", &ic.SofAlt{Present: ic.SofAltPrC, C: bp(true)}, el("c", bl(true)))
	return cs
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for ; v > 0; v /= 10 {
		b = append([]byte{byte('0' + v%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestInlConstrRoundTrip(t *testing.T) {
	for _, c := range icCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
	}
}

// TestInlConstrCConverter compares every case with the C converter built from
// the same C tree: its APER of the XER value is the Go APER, and its XER of
// the Go APER is the XER value.
func TestInlConstrCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range icCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref, ok := siConv(t, bin, c, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		if re, ok := siConv(t, bin, c, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re, ok := siConv(t, bin, c, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}
