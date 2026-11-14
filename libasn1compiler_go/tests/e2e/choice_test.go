package e2e

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	rs "asn1cgo.test/go/reserved"
	tc "asn1cgo.test/go/twochoice"
)

// CHOICE alternatives (and SEQUENCE members, enumerators) named after a C
// reserved word (tests/e2e/choice.asn). asn1c upper-cases the first letter
// of the union member (`Explicit`) but keeps the lower-case _PR constant
// (`C_PR_explicit`); building the module is the first check. Every
// alternative is encoded in Go, compared with the C converter's APER of the
// same value written as XER, and decoded back. Copied into the generated
// module by tests/run-e2e.sh with default_test.go (the converter helpers).
func TestReservedRoundTrip(t *testing.T) {
	bin := converter(t)
	yes, i5, i2 := true, int64(5), int64(2)
	oct := []byte{0xAB, 0xCD}
	cases := []struct {
		pdu string
		xer string
		enc func() ([]byte, error)
		chk func(aper []byte) bool
	}{
		{"RsH", "<RsH><explicit><true/></explicit><int>2</int></RsH>",
			func() ([]byte, error) { v := rs.RsH{Explicit: true, Int: &i2}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsH(b); return err == nil && v.Explicit && v.Int != nil && *v.Int == 2 }},
		{"RsC", "<RsC><explicit><true/></explicit></RsC>",
			func() ([]byte, error) { v := rs.RsC{Present: rs.RsCPrExplicit, Explicit: &yes}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsC(b); return err == nil && v.Present == rs.RsCPrExplicit && *v.Explicit }},
		{"RsC", "<RsC><x></x></RsC>",
			func() ([]byte, error) { v := rs.RsC{Present: rs.RsCPrX}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsC(b); return err == nil && v.Present == rs.RsCPrX }},
		{"RsE", "<RsE><auto/></RsE>",
			func() ([]byte, error) { e := rs.RsEAuto; return e.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsE(b); return err == nil && *v == rs.RsEAuto }},
		{"RsR", "<RsR><explicit><true/></explicit></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrExplicit, Explicit: &yes}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrExplicit && *v.Explicit }},
		{"RsR", "<RsR><int>5</int></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrInt, Int: &i5}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrInt && *v.Int == 5 }},
		{"RsR", "<RsR><auto>ABCD</auto></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrAuto, Auto: &oct}; return v.Encode() },
			func(b []byte) bool {
				v, err := rs.DecodeRsR(b)
				return err == nil && v.Present == rs.RsRPrAuto && bytes.Equal(*v.Auto, oct)
			}},
		{"RsR", "<RsR><default><a>3</a></default></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrDefault, Default: &rs.RsRDefault{A: 3}}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrDefault && v.Default.A == 3 }},
		{"RsR", "<RsR><struct><q>3</q></struct></RsR>",
			func() ([]byte, error) {
				q := int64(3)
				v := rs.RsR{Present: rs.RsRPrStruct, Struct: &rs.RsRStruct{Present: rs.RsRStructPrQ, Q: &q}}; return v.Encode()
			},
			func(b []byte) bool {
				v, err := rs.DecodeRsR(b)
				return err == nil && v.Present == rs.RsRPrStruct && v.Struct.Present == rs.RsRStructPrQ && *v.Struct.Q == 3
			}},
		{"RsR", "<RsR><x></x></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrX}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrX }},
		{"RsR", "<RsR><static></static></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrStatic}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrStatic }},
	}
	for _, c := range cases {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.xer, err)
			continue
		}
		if ref := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER % x", c.xer, aper, ref)
		}
		if got := normXML(convPDU(t, bin, c.pdu, aper, "-iaper", "-oxer")); got != normXML([]byte(c.xer)) {
			t.Errorf("C XER of the Go APER = %s, want %s", got, c.xer)
		}
		if !c.chk(aper) {
			t.Errorf("%s: decode mismatch", c.xer)
		}
	}
}

// A SEQUENCE with more than one inline CHOICE member (tests/e2e/choice.asn):
// each inline CHOICE needs its own scope in the generated fill and size
// bodies. Every combination of alternatives of the two CHOICEs is encoded in
// Go, compared with the C converter's APER of the same value written as XER,
// and decoded back. The cases cover plain alternatives, SEQUENCE alternatives
// (also empty), an INTEGER member between the CHOICEs and an inline CHOICE
// inside an inline SEQUENCE alternative of an inline CHOICE. Copied into the
// generated module by tests/run-e2e.sh together with default_test.go (the
// converter helpers).
type tcCase struct {
	name, pdu, xer string
	enc            func() ([]byte, error)
	dec            func([]byte) error
}

func tcMk[T any](name, pdu, xer string, v T, dec func([]byte) (*T, error)) tcCase {
	return tcCase{
		name: name, pdu: pdu, xer: "<" + pdu + ">" + xer + "</" + pdu + ">",
		enc: func() ([]byte, error) { return any(&v).(siEncoder).Encode() },
		dec: func(b []byte) error {
			got, err := dec(b)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(*got, v) {
				return fmt.Errorf("decoded %+v, want %+v", *got, v)
			}
			return nil
		},
	}
}

func tcCases() []tcCase {
	var cs []tcCase
	tr, fl := true, false
	i := func(v int64) *int64 { return &v }

	// T: every alternative of m with every alternative of p.
	for _, m := range []struct {
		v   tc.TwoChM
		xer string
	}{
		{tc.TwoChM{Present: tc.TwoChMPrF, F: &tr}, "<f><true/></f>"},
		{tc.TwoChM{Present: tc.TwoChMPrF, F: &fl}, "<f><false/></f>"},
		{tc.TwoChM{Present: tc.TwoChMPrT}, "<t></t>"},
	} {
		for _, p := range []struct {
			v   tc.TwoChP
			xer string
		}{
			{tc.TwoChP{Present: tc.TwoChPPrB, B: &tr}, "<b><true/></b>"},
			{tc.TwoChP{Present: tc.TwoChPPrB, B: &fl}, "<b><false/></b>"},
			{tc.TwoChP{Present: tc.TwoChPPrA}, "<a></a>"},
		} {
			cs = append(cs, tcMk("t "+m.xer+p.xer, "TwoCh", "<m>"+m.xer+"</m><p>"+p.xer+"</p>",
				tc.TwoCh{M: m.v, P: p.v}, tc.DecodeTwoCh))
		}
	}

	// S: SEQUENCE alternatives (one empty) on both CHOICEs, an INTEGER between.
	for _, m := range []struct {
		v   tc.TwoSeqM
		xer string
	}{
		{tc.TwoSeqM{Present: tc.TwoSeqMPrF, F: &tc.TwoSeqMF{X: true}}, "<f><x><true/></x></f>"},
		{tc.TwoSeqM{Present: tc.TwoSeqMPrF, F: &tc.TwoSeqMF{X: false}}, "<f><x><false/></x></f>"},
		{tc.TwoSeqM{Present: tc.TwoSeqMPrE, E: &tc.TwoSeqME{}}, "<e></e>"},
		{tc.TwoSeqM{Present: tc.TwoSeqMPrK, K: i(9)}, "<k>9</k>"},
	} {
		for _, p := range []struct {
			v   tc.TwoSeqP
			xer string
		}{
			{tc.TwoSeqP{Present: tc.TwoSeqPPrB, B: &tc.TwoSeqPB{Y: 0}}, "<b><y>0</y></b>"},
			{tc.TwoSeqP{Present: tc.TwoSeqPPrB, B: &tc.TwoSeqPB{Y: 3}}, "<b><y>3</y></b>"},
			{tc.TwoSeqP{Present: tc.TwoSeqPPrA}, "<a></a>"},
		} {
			for _, n := range []int64{0, 200} {
				nx := "<n>0</n>"
				if n == 200 {
					nx = "<n>200</n>"
				}
				cs = append(cs, tcMk("s "+m.xer+nx+p.xer, "TwoSeq", "<m>"+m.xer+"</m>"+nx+"<p>"+p.xer+"</p>",
					tc.TwoSeq{M: m.v, N: n, P: p.v}, tc.DecodeTwoSeq))
			}
		}
	}

	// N: an inline CHOICE (two of them in one alternative) inside an inline
	// SEQUENCE alternative of an inline CHOICE.
	type nq struct {
		v   tc.TwoNestMSQ
		xer string
	}
	type nr struct {
		v   tc.TwoNestMSR
		xer string
	}
	qs := []nq{
		{tc.TwoNestMSQ{Present: tc.TwoNestMSQPrU, U: &tr}, "<u><true/></u>"},
		{tc.TwoNestMSQ{Present: tc.TwoNestMSQPrU, U: &fl}, "<u><false/></u>"},
		{tc.TwoNestMSQ{Present: tc.TwoNestMSQPrV}, "<v></v>"},
	}
	rs := []nr{
		{tc.TwoNestMSR{Present: tc.TwoNestMSRPrC, C: i(3)}, "<c>3</c>"},
		{tc.TwoNestMSR{Present: tc.TwoNestMSRPrD}, "<d></d>"},
	}
	var ms []struct {
		v   tc.TwoNestM
		xer string
	}
	for _, q := range qs {
		for _, r := range rs {
			ms = append(ms, struct {
				v   tc.TwoNestM
				xer string
			}{tc.TwoNestM{Present: tc.TwoNestMPrS, S: &tc.TwoNestMS{Q: q.v, R: r.v}},
				"<s><q>" + q.xer + "</q><r>" + r.xer + "</r></s>"})
		}
	}
	ms = append(ms,
		struct {
			v   tc.TwoNestM
			xer string
		}{tc.TwoNestM{Present: tc.TwoNestMPrZ, Z: &tr}, "<z><true/></z>"},
		struct {
			v   tc.TwoNestM
			xer string
		}{tc.TwoNestM{Present: tc.TwoNestMPrZ, Z: &fl}, "<z><false/></z>"})
	var ps []struct {
		v   tc.TwoNestP
		xer string
	}
	for _, q := range qs {
		ps = append(ps, struct {
			v   tc.TwoNestP
			xer string
		}{tc.TwoNestP{Present: tc.TwoNestPPrS, S: &tc.TwoNestPS{Q: tc.TwoNestPSQ{Present: tc.TwoNestPSQPr(q.v.Present), U: q.v.U}}},
			"<s><q>" + q.xer + "</q></s>"})
	}
	ps = append(ps, struct {
		v   tc.TwoNestP
		xer string
	}{tc.TwoNestP{Present: tc.TwoNestPPrZ}, "<z></z>"})
	for _, m := range ms {
		for _, p := range ps {
			cs = append(cs, tcMk("n "+m.xer+p.xer, "TwoNest", "<m>"+m.xer+"</m><p>"+p.xer+"</p>",
				tc.TwoNest{M: m.v, P: p.v}, tc.DecodeTwoNest))
		}
	}

	// E: an empty SEQUENCE alternative selected, as the last allocation.
	em := &tc.EmTopE{}
	cs = append(cs,
		tcMk("et e", "EmTop", "<e></e>", tc.EmTop{Present: tc.EmTopPrE, E: em}, tc.DecodeEmTop),
		tcMk("et k", "EmTop", "<k><true/></k>", tc.EmTop{Present: tc.EmTopPrK, K: &tr}, tc.DecodeEmTop),
		tcMk("es e", "EmSeq", "<m><e></e></m>", tc.EmSeq{M: tc.EmSeqM{Present: tc.EmSeqMPrE, E: &tc.EmSeqME{}}}, tc.DecodeEmSeq),
		tcMk("es k", "EmSeq", "<m><k><false/></k></m>", tc.EmSeq{M: tc.EmSeqM{Present: tc.EmSeqMPrK, K: &fl}}, tc.DecodeEmSeq))
	return cs
}

func TestTwoChoiceRoundTrip(t *testing.T) {
	bin := converter(t)
	cs := tcCases()
	if len(cs) != 69 {
		t.Fatalf("only %d cases", len(cs))
	}
	for _, c := range cs {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER % x", c.name, aper, ref)
		}
		if got := normXML(convPDU(t, bin, c.pdu, aper, "-iaper", "-oxer")); got != normXML([]byte(c.xer)) {
			t.Errorf("%s: C XER of the Go APER = %s, want %s", c.name, got, c.xer)
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
		}
	}
}
