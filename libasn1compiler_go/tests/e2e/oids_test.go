// OBJECT IDENTIFIER and RELATIVE-OID (tests/e2e/oids.asn). Copied into the
// generated module by tests/run-e2e.sh together with default_test.go (the
// converter helpers), seqof_test.go (siCase / siMk / siConv) and
// strings_test.go (stCase / stMk / stNorm).
//
// Both types are []uint64 arcs in Go. The generated C converters fill the tree
// with OBJECT_IDENTIFIER_set_arcs / RELATIVE_OID_set_arcs and read it with
// the _get_arcs functions, so the C runtime decides what is a valid value.
// What it enforces (OBJECT_IDENTIFIER.c):
//
//   - an arc is 32 bits: the Go glue rejects an arc above 4294967295 before
//     any C call (it never truncates);
//   - OBJECT IDENTIFIER: at least two arcs; first arc 0, 1 or 2; second arc
//     below 40 when the first is 0 or 1; second arc at most 4294967215
//     (4294967295 - 80) when the first is 2;
//   - RELATIVE-OID: any number of arcs, including none.
//
// Per value: Go APER == the C converter's APER of the same value written as
// XER; Go's decode gives the value back; the converter's XER of the Go APER is
// the given XER and re-encodes to the same APER. Shapes covered:
//
//	top level     both types              (otCases, "top" rows)
//	member        mandatory and OPTIONAL  (Rec), plain and behind a named type
//	SEQUENCE OF   elements of both types  (OidList, RoidList, NamedList, ...)
//	CHOICE alt    both types, plain and named (Alt)
//	extension     both types              (Ext)
//
// The allocation-fault sweep over the same values is in faults_test.go.
package e2e

import (
	"bytes"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	oi "asn1cgo.test/go/oids"
	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
)

func otDots(a []uint64) string {
	s := make([]string, len(a))
	for i, v := range a {
		s[i] = strconv.FormatUint(v, 10)
	}
	return strings.Join(s, ".")
}

// otSeq is 1, 2, ..., n (a long arc list: more than the 16 slots the
// converter first offers _get_arcs, so the grow-and-retry path runs).
func otSeq(first []uint64, n int) []uint64 {
	a := append([]uint64(nil), first...)
	for i := 1; i <= n; i++ {
		a = append(a, uint64(i))
	}
	return a
}

func otOid(name string, a []uint64) stCase {
	return stMk(name, "OidTop", stEl("OidTop", otDots(a)), stp(oi.OidTop(a)), oi.DecodeOidTop)
}

func otRoid(name string, a []uint64) stCase {
	return stMk(name, "RoidTop", stEl("RoidTop", otDots(a)), stp(oi.RoidTop(a)), oi.DecodeRoidTop)
}

func otCases() []stCase {
	var cs []stCase
	add := func(c stCase) { cs = append(cs, c) }

	// ---- OBJECT IDENTIFIER, top level ----
	add(otOid("oid-private-enterprise", []uint64{1, 3, 6, 1, 4, 1, 53148}))
	add(otOid("oid-2-999-1", []uint64{2, 999, 1})) // large second arc under root 2
	add(otOid("oid-0-0", []uint64{0, 0}))          // the smallest valid value
	add(otOid("oid-0-39", []uint64{0, 39}))
	add(otOid("oid-1-0", []uint64{1, 0}))
	add(otOid("oid-1-39", []uint64{1, 39}))
	add(otOid("oid-2-0", []uint64{2, 0}))
	add(otOid("oid-2-39", []uint64{2, 39}))
	add(otOid("oid-2-40", []uint64{2, 40}))
	add(otOid("oid-2-47", []uint64{2, 47}))
	add(otOid("oid-2-48", []uint64{2, 48}))
	add(otOid("oid-max-arc", []uint64{1, 3, math.MaxUint32}))
	add(otOid("oid-max-arc-2-999", []uint64{2, 999, math.MaxUint32}))
	add(otOid("oid-all-max-arcs", []uint64{1, 3, math.MaxUint32, math.MaxUint32, math.MaxUint32}))
	add(otOid("oid-2-max-second", []uint64{2, math.MaxUint32 - 80}))
	add(otOid("oid-arc-2^28", []uint64{1, 3, 1 << 28}))
	add(otOid("oid-arc-2^31", []uint64{1, 3, 1 << 31}))
	add(otOid("oid-long-16", otSeq([]uint64{1, 3}, 14))) // exactly the 16 first slots
	add(otOid("oid-long-17", otSeq([]uint64{1, 3}, 15))) // one over: grow and retry
	add(otOid("oid-long-40", otSeq([]uint64{1, 3}, 38)))
	add(otOid("oid-long-300", otSeq([]uint64{2, 5}, 298)))

	// ---- RELATIVE-OID, top level ----
	add(otRoid("roid-8571-3-2", []uint64{8571, 3, 2}))
	add(otRoid("roid-1", []uint64{0}))
	add(otRoid("roid-max", []uint64{math.MaxUint32}))
	add(otRoid("roid-mixed", []uint64{0, 127, 128, 16383, 16384, math.MaxUint32, 0}))
	add(otRoid("roid-long-40", otSeq(nil, 40)))
	// an empty RELATIVE-OID is allowed by the C runtime
	// (RELATIVE_OID_constraint is asn_generic_no_constraint, _set_arcs takes
	// zero arcs): a non-nil empty slice round-trips (a nil one comes back as
	// the empty slice, which is how Decode spells "no arcs")
	add(otRoid("roid-empty", []uint64{}))

	// ---- members ----
	full := func(opt bool) *oi.OidRec {
		r := &oi.OidRec{
			Oid: []uint64{1, 3, 6, 1}, Roid: []uint64{8571, 3, 2},
			Named: oi.OidNamed{2, 999, 1}, Rnamed: oi.RoidNamed{1, 2},
			Flag: true,
		}
		if opt {
			r.Oido = &[]uint64{0, 0}
			r.Roido = &[]uint64{}
			n := oi.OidNamed{1, 2, 3}
			r.Nameo = &n
			rn := oi.RoidNamed{7}
			r.Rnameo = &rn
		}
		return r
	}
	add(stMk("rec-absent", "OidRec", "", full(false), oi.DecodeOidRec,
		"<oid>1.3.6.1</oid>", "<roid>8571.3.2</roid>", "<named>2.999.1</named>", "<rnamed>1.2</rnamed>"))
	add(stMk("rec-present", "OidRec", "", full(true), oi.DecodeOidRec,
		"<oid>1.3.6.1</oid>", "<oido>0.0</oido>", "<roid>8571.3.2</roid>", "<roido></roido>",
		"<named>2.999.1</named>", "<nameo>1.2.3</nameo>", "<rnamed>1.2</rnamed>", "<rnameo>7</rnameo>"))
	long := full(true)
	long.Oid = otSeq([]uint64{1, 3}, 30)
	long.Oido = &[]uint64{}
	*long.Oido = otSeq([]uint64{2, 100}, 20)
	long.Named = otSeq([]uint64{0, 9}, 25)
	add(stMk("rec-long", "OidRec", "", long, oi.DecodeOidRec,
		"<oid>"+otDots(long.Oid)+"</oid>", "<oido>"+otDots(*long.Oido)+"</oido>", "<named>"+otDots(long.Named)+"</named>"))

	// ---- SEQUENCE OF ----
	el := func(tag string, a []uint64) string { return stEl(tag, otDots(a)) }
	oidEls := func(vs ...[]uint64) []string {
		var o []string
		for _, v := range vs {
			o = append(o, el("OBJECT_IDENTIFIER", v))
		}
		return o
	}
	roidEls := func(vs ...[]uint64) []string {
		var o []string
		for _, v := range vs {
			o = append(o, el("RELATIVE_OID", v))
		}
		return o
	}
	add(stMk("oidlist", "OidList", siList("OidList", oidEls([]uint64{1, 3}, []uint64{2, 999, 1}, []uint64{0, 0})...),
		&oi.OidList{{1, 3}, {2, 999, 1}, {0, 0}}, oi.DecodeOidList))
	// (an empty SEQUENCE OF decodes as a nil slice, here as for every list type)
	add(stMk("oidlist-empty", "OidList", siList("OidList"), new(oi.OidList), oi.DecodeOidList))
	add(stMk("oidlist-long", "OidList", siList("OidList", oidEls(otSeq([]uint64{1, 3}, 20), []uint64{1, 3})...),
		&oi.OidList{otSeq([]uint64{1, 3}, 20), {1, 3}}, oi.DecodeOidList))
	add(stMk("roidlist", "RoidList", siList("RoidList", roidEls([]uint64{8571, 3, 2}, []uint64{0}, []uint64{})...),
		&oi.RoidList{{8571, 3, 2}, {0}, {}}, oi.DecodeRoidList))
	add(stMk("namedlist", "NamedList", "", &oi.NamedList{{1, 3}, {2, 5, 6}}, oi.DecodeNamedList,
		"1.3", "2.5.6"))
	add(stMk("rnamedlist", "RnamedList", "", &oi.RnamedList{{9}, {}, {1, 2, 3}}, oi.DecodeRnamedList,
		"9", "1.2.3"))
	add(stMk("holder", "OidHolder", "", &oi.OidHolder{
		Oids:  oi.OidHolderOids{{1, 3, 6}, {2, 1}},
		Roids: oi.OidHolderRoids{{4, 5}},
		Flag:  true,
	}, oi.DecodeOidHolder, "1.3.6", "2.1", "4.5"))
	add(stMk("holder-empty-oids", "OidHolder", "", &oi.OidHolder{
		Oids:  nil,
		Roids: oi.OidHolderRoids{{}, {1}},
	}, oi.DecodeOidHolder))

	// ---- CHOICE alternatives ----
	alt := func(name string, a *oi.OidAlt, has ...string) {
		add(stMk(name, "OidAlt", "", a, oi.DecodeOidAlt, has...))
	}
	nm := oi.OidNamed{2, 999, 1}
	rn := oi.RoidNamed{8571, 3, 2}
	flag := true
	alt("alt-oid", &oi.OidAlt{Present: oi.OidAltPrOid, Oid: &[]uint64{1, 3, 6, 1}}, "<oid>1.3.6.1</oid>")
	alt("alt-roid", &oi.OidAlt{Present: oi.OidAltPrRoid, Roid: &[]uint64{8571, 3, 2}}, "<roid>8571.3.2</roid>")
	alt("alt-roid-empty", &oi.OidAlt{Present: oi.OidAltPrRoid, Roid: &[]uint64{}}, "<roid></roid>")
	alt("alt-named", &oi.OidAlt{Present: oi.OidAltPrNamed, Named: &nm}, "<named>2.999.1</named>")
	alt("alt-rnamed", &oi.OidAlt{Present: oi.OidAltPrRnamed, Rnamed: &rn}, "<rnamed>8571.3.2</rnamed>")
	alt("alt-flag", &oi.OidAlt{Present: oi.OidAltPrFlag, Flag: &flag}, "<flag>")

	// ---- extension additions ----
	add(stMk("ext-none", "OidExt", "", &oi.OidExt{A: 3}, oi.DecodeOidExt))
	add(stMk("ext-all", "OidExt", "", &oi.OidExt{A: 3, Oid: &[]uint64{1, 3, 6}, Roid: &[]uint64{4, 5}}, oi.DecodeOidExt,
		"<oid>1.3.6</oid>", "<roid>4.5</roid>"))
	add(stMk("ext-roid-only", "OidExt", "", &oi.OidExt{A: 1, Roid: &[]uint64{}}, oi.DecodeOidExt, "<roid></roid>"))

	return cs
}

func TestOidsRoundTrip(t *testing.T) {
	for _, c := range otCases() {
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

func TestOidsCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range otCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if c.xer != "" && !otEmptyRoid.MatchString(c.xer) {
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
		// The C runtime's XER decoder cannot read an empty RELATIVE-OID back
		// (<roid></roid>: "Input processing error"), although its encoder
		// writes one; the APER of such a value is checked by the other
		// directions above. The trailing newline of the converter's output is
		// dropped: after an OBJECT IDENTIFIER, RELATIVE-OID (or INTEGER) PDU
		// the converter reports "Unexpected end of input" for it.
		if otEmptyRoid.Match(xer) {
			continue
		}
		if re, ok := siConv(t, bin, c.siCase, bytes.TrimSpace(xer), "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

var otEmptyRoid = regexp.MustCompile(`<(RoidTop|RELATIVE_OID|RoidNamed|roid|roido|rnamed|rnameo)></`)

// Hand-computed APER: the contents octets are the BER ones (X.690 8.19, 8.20),
// preceded by the aligned length octet.
func TestOidsHandMadeAPER(t *testing.T) {
	for _, c := range []struct {
		name string
		enc  func() ([]byte, error)
		want []byte
	}{
		// 1.3.6.1.4.1.53148: 2B 06 01 04 01, 53148 = 3*128^2 + 31*128 + 28 = 83 9F 1C
		{"oid-pen", func() ([]byte, error) { return stp(oi.OidTop{1, 3, 6, 1, 4, 1, 53148}).Encode() },
			[]byte{0x08, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x9F, 0x1C}},
		// 2.999.1: (80+999)=1079 = 8 37 -> 88 37, then 01
		{"oid-2-999-1", func() ([]byte, error) { return stp(oi.OidTop{2, 999, 1}).Encode() },
			[]byte{0x03, 0x88, 0x37, 0x01}},
		{"oid-0-0", func() ([]byte, error) { return stp(oi.OidTop{0, 0}).Encode() },
			[]byte{0x01, 0x00}},
		// 1.3.4294967295: 43, then 4294967295 = 8F FF FF FF 7F
		{"oid-max-arc", func() ([]byte, error) { return stp(oi.OidTop{1, 3, math.MaxUint32}).Encode() },
			[]byte{0x06, 0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F}},
		// 8571.3.2: 8571 = 0x217B = 1000010 1111011 -> C2 7B
		{"roid-8571-3-2", func() ([]byte, error) { return stp(oi.RoidTop{8571, 3, 2}).Encode() },
			[]byte{0x04, 0xC2, 0x7B, 0x03, 0x02}},
		{"roid-empty", func() ([]byte, error) { return stp(oi.RoidTop{}).Encode() },
			[]byte{0x00}},
	} {
		got, err := c.enc()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER % x, want % x", c.name, got, c.want)
		}
	}
}

// otBad: a value Encode must refuse. glue is set for the errors the generated
// Go glue raises itself (an arc the C type cannot hold); the others are the C
// runtime's _set_arcs rejections, reported as constraint violations.
type otBad struct {
	name string
	v    stEnc
	glue string
}

func otBadCases() []otBad {
	var bs []otBad
	add := func(name string, v stEnc, glue string) { bs = append(bs, otBad{name, v, glue}) }
	const big = "exceeds 4294967295"

	// an arc above the 32-bit C arc type
	add("oid-arc-2^32", stp(oi.OidTop{1, 3, 1 << 32}), big)
	add("oid-arc-2^32-first", stp(oi.OidTop{1 << 32, 3}), big)
	add("oid-arc-2^32-second", stp(oi.OidTop{1, 1 << 32}), big)
	add("oid-arc-max-uint64", stp(oi.OidTop{1, 3, math.MaxUint64}), big)
	add("roid-arc-2^32", stp(oi.RoidTop{5, 1 << 32}), big)
	add("roid-arc-max-uint64", stp(oi.RoidTop{math.MaxUint64}), big)
	// OBJECT IDENTIFIER_set_arcs rejections
	add("oid-3-1", stp(oi.OidTop{3, 1}), "")
	add("oid-3-0", stp(oi.OidTop{3, 0}), "")
	add("oid-1-arc", stp(oi.OidTop{1}), "")
	add("oid-2-arc-only", stp(oi.OidTop{2}), "")
	add("oid-empty", stp(oi.OidTop{}), "")
	add("oid-nil", stp(oi.OidTop(nil)), "")
	add("oid-0-40", stp(oi.OidTop{0, 40}), "")
	add("oid-1-40", stp(oi.OidTop{1, 40}), "")
	add("oid-1-4294967295", stp(oi.OidTop{1, math.MaxUint32}), "")
	add("oid-2-over-max-second", stp(oi.OidTop{2, math.MaxUint32 - 79}), "")
	add("oid-2-max-arc-second", stp(oi.OidTop{2, math.MaxUint32}), "")
	add("oid-3-first-with-more", stp(oi.OidTop{4, 0, 1, 2}), "")
	// the same checks behind members, lists, alternatives, extensions
	bad := &oi.OidRec{Oid: []uint64{1}, Roid: []uint64{1}, Named: oi.OidNamed{1, 3}}
	add("rec-oid-1-arc", bad, "")
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1}, Named: oi.OidNamed{1, 3}, Oido: &[]uint64{3, 3}}
	add("rec-oido-3-3", bad, "")
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1 << 32}, Named: oi.OidNamed{1, 3}}
	add("rec-roid-big", bad, big)
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1}, Named: oi.OidNamed{1, 3}, Roido: &[]uint64{1, 1 << 40}}
	add("rec-roido-big", bad, big)
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1}, Named: oi.OidNamed{1, 50}}
	add("rec-named-1-50", bad, "")
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1}, Named: oi.OidNamed{1, 3}, Rnamed: oi.RoidNamed{1 << 33}}
	add("rec-rnamed-big", bad, big)
	bad = &oi.OidRec{Oid: []uint64{1, 3}, Roid: []uint64{1}, Named: oi.OidNamed{1, 3}, Nameo: &oi.OidNamed{7}}
	add("rec-nameo-1-arc", bad, "")
	add("oidlist-elem", stp(oi.OidList{{1, 3}, {1, 40}}), "")
	add("oidlist-elem-big", stp(oi.OidList{{1, 3}, {1, 3, 1 << 32}}), big)
	add("roidlist-elem-big", stp(oi.RoidList{{1}, {1 << 32}}), big)
	add("namedlist-elem", stp(oi.NamedList{{1, 3}, {9, 9}}), "")
	add("holder-oids-elem", &oi.OidHolder{Oids: oi.OidHolderOids{{1}}, Roids: oi.OidHolderRoids{{1}}}, "")
	add("holder-roids-elem-big", &oi.OidHolder{Oids: oi.OidHolderOids{{1, 3}}, Roids: oi.OidHolderRoids{{1 << 32}}}, big)
	add("alt-oid", &oi.OidAlt{Present: oi.OidAltPrOid, Oid: &[]uint64{4, 4}}, "")
	add("alt-roid-big", &oi.OidAlt{Present: oi.OidAltPrRoid, Roid: &[]uint64{1 << 32}}, big)
	add("alt-named", &oi.OidAlt{Present: oi.OidAltPrNamed, Named: &oi.OidNamed{0, 99}}, "")
	add("alt-rnamed-big", &oi.OidAlt{Present: oi.OidAltPrRnamed, Rnamed: &oi.RoidNamed{1 << 32}}, big)
	add("ext-oid", &oi.OidExt{A: 1, Oid: &[]uint64{5, 5}}, "")
	add("ext-roid-big", &oi.OidExt{A: 1, Roid: &[]uint64{1 << 32}}, big)
	return bs
}

func TestOidsEncodeErrors(t *testing.T) {
	for _, c := range otBadCases() {
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
		if !errors.Is(err, rt.ErrConstraint) {
			t.Errorf("%s: err = %v, want rt.ErrConstraint", c.name, err)
		}
		if c.glue != "" && !strings.Contains(re.Message, c.glue) {
			t.Errorf("%s: message %q lacks %q", c.name, re.Message, c.glue)
		}
		balanced(t, c.name)
	}
}

// Hand-made APER whose C decode succeeds (the contents are an opaque octet
// string to the PER codec) but whose contents are not valid arcs: the Go
// decode must return an rt.ErrDecode error, not a short or empty value.
func TestOidsDecodeErrors(t *testing.T) {
	oidDec := func(b []byte) error { _, e := oi.DecodeOidTop(b); return e }
	roidDec := func(b []byte) error { _, e := oi.DecodeRoidTop(b); return e }
	listDec := func(b []byte) error { _, e := oi.DecodeOidList(b); return e }
	rlistDec := func(b []byte) error { _, e := oi.DecodeRoidList(b); return e }
	// APER of a top-level OCTET STRING-shaped value: aligned length octet, contents
	oct := func(c ...byte) []byte { return append([]byte{byte(len(c))}, c...) }
	cases := []struct {
		name string
		wire []byte
		dec  func([]byte) error
		code error // the rt sentinel, rt.ErrDecode unless set
	}{
		{"oid-trailing-high-bit", oct(0x2B, 0x06, 0x81), oidDec, nil},
		{"oid-only-high-bit", oct(0x81), oidDec, nil},
		{"oid-high-bits-then-end", oct(0x2B, 0x86, 0x80, 0x80), oidDec, nil},
		{"oid-arc-over-32-bits", oct(0x2B, 0x90, 0x80, 0x80, 0x80, 0x00), oidDec, nil},
		{"oid-arc-way-over", oct(0x2B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F), oidDec, nil},
		// an OBJECT IDENTIFIER needs at least one sub-identifier: the C constraint
		// check rejects it when the value is decoded
		{"oid-empty-contents", oct(), oidDec, rt.ErrConstraint},
		{"roid-trailing-high-bit", oct(0x01, 0x81), roidDec, nil},
		{"roid-arc-over-32-bits", oct(0x90, 0x80, 0x80, 0x80, 0x00), roidDec, nil},
		{"oidlist-elem-trailing-high-bit", []byte{0x01, 0x02, 0x2B, 0x81}, listDec, nil},
		{"roidlist-elem-trailing-high-bit", []byte{0x01, 0x01, 0x81}, rlistDec, nil},
	}
	for _, c := range cases {
		err := c.dec(c.wire)
		var re *rt.Error
		if !errors.As(err, &re) {
			t.Errorf("%s: Decode % x err = %v, want an *rt.Error", c.name, c.wire, err)
			continue
		}
		want := c.code
		if want == nil {
			want = rt.ErrDecode
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: Decode % x err = %v, want %v", c.name, c.wire, err, want)
		}
		balanced(t, c.name)
	}
	// The same framing with valid contents decodes (the cases above fail
	// because of the contents, not the framing).
	if v, err := oi.DecodeOidTop(oct(0x2B, 0x06, 0x01)); err != nil || len(*v) != 4 || (*v)[2] != 6 {
		t.Errorf("valid OID: %v %v", v, err)
	}
	if v, err := oi.DecodeRoidTop(oct(0x01, 0x02)); err != nil || len(*v) != 2 {
		t.Errorf("valid RELATIVE-OID: %v %v", v, err)
	}
	if v, err := oi.DecodeRoidTop(oct()); err != nil || v == nil || len(*v) != 0 {
		t.Errorf("empty RELATIVE-OID: %v %v", v, err)
	}
	// the largest decodable arcs
	if v, err := oi.DecodeOidTop(oct(0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F)); err != nil || (*v)[2] != math.MaxUint32 {
		t.Errorf("max arc: %v %v", v, err)
	}
	// first octet 0x7F... : (2, MaxUint32-80) is what 4294967295 decodes to
	if v, err := oi.DecodeOidTop(oct(0x8F, 0xFF, 0xFF, 0xFF, 0x7F)); err != nil || len(*v) != 2 || (*v)[0] != 2 || (*v)[1] != math.MaxUint32-80 {
		t.Errorf("max first value: %v %v", v, err)
	}
}

// A nil pointer to the OPTIONAL / ALT slot is "absent" (OPTIONAL) or a CHOICE
// error (alternative), exactly as for the other pointer-held types.
func TestOidsChoiceNil(t *testing.T) {
	_, err := (&oi.OidAlt{Present: oi.OidAltPrOid}).Encode()
	if !errors.Is(err, rt.ErrChoiceBad) {
		t.Errorf("nil oid alt: err = %v, want rt.ErrChoiceBad", err)
	}
	_, err = (&oi.OidAlt{Present: oi.OidAltPrRnamed}).Encode()
	if !errors.Is(err, rt.ErrChoiceBad) {
		t.Errorf("nil rnamed alt: err = %v, want rt.ErrChoiceBad", err)
	}
}

// Decoded values own their memory: mutating one cannot reach another decode.
func TestOidsDecodedValuesAreIndependent(t *testing.T) {
	wire, err := stp(oi.OidTop{1, 3, 6, 1}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, err := oi.DecodeOidTop(wire)
	if err != nil {
		t.Fatal(err)
	}
	b, err := oi.DecodeOidTop(wire)
	if err != nil {
		t.Fatal(err)
	}
	(*a)[0] = 9
	if (*b)[0] != 1 {
		t.Errorf("second decode shares memory with the first: %v", *b)
	}
	if cap(*a) != len(*a) {
		t.Logf("decoded OID capacity %d, length %d", cap(*a), len(*a))
	}
}
