// A SEQUENCE with more than one inline CHOICE member (tests/e2e/twochoice.asn):
// each inline CHOICE needs its own scope in the generated fill and size
// bodies. Every combination of alternatives of the two CHOICEs is encoded in
// Go, compared with the C converter's APER of the same value written as XER,
// and decoded back. The cases cover plain alternatives, SEQUENCE alternatives
// (also empty), an INTEGER member between the CHOICEs and an inline CHOICE
// inside an inline SEQUENCE alternative of an inline CHOICE. Copied into the
// generated module by tests/run-e2e.sh together with default_test.go (the
// converter helpers).
package e2e

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	tc "asn1cgo.test/go/twochoice"
)

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
