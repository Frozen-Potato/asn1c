// Information object class forms (tests/e2e/iocforms.asn): an open-type
// SEQUENCE as a PDU of its own, a class field whose type is written inline
// and built-in types written directly in the objects. Copied into the generated module by tests/run-e2e.sh
// together with seqof_test.go (siCase helpers), bits_test.go (bsXML) and
// default_test.go (the C converter).
//
// Per case: the exact APER bytes (X.691, worked out by hand), Go's decode
// gives the value back, and the C converter agrees (XER -> APER, APER
// re-encode, APER -> XER).
package e2e

import (
    "bytes"
    "encoding/hex"
    "testing"

    iof "asn1cgo.test/go/iocforms"
)

type ifCase struct {
    siCase
    aper string // hex
}

func ifCases() []ifCase {
    var cs []ifCase
    inl := func(name, aper, xer string, v iof.InlineIE) {
        cs = append(cs, ifCase{siMk(name, "InlineIE", xer, &v, iof.DecodeInlineIE), aper})
    }
    blt := func(name, aper, xer string, v iof.BuiltinIE) {
        cs = append(cs, ifCase{siMk(name, "BuiltinIE", xer, &v, iof.DecodeBuiltinIE), aper})
    }
    ie := func(pdu string, id int64, alt string) string {
        return "<" + pdu + "><id>" + itoa(id) + "</id><value>" + alt + "</value></" + pdu + ">"
    }

    // inline class-field type: the id is a plain int64, a literal (1) and a
    // value reference (id-flag = 7) alike
    inl("inline-literal", "010105", ie("InlineIE", 1, "<Small>5</Small>"), iof.NewInlineIEId1(5))
    inl("inline-valueref", "070180", ie("InlineIE", 7, "<OnOff><true/></OnOff>"), iof.NewInlineIEId7(true))

    // built-in types in the objects
    blt("builtin-boolean", "010180", ie("BuiltinIE", 1, "<BOOLEAN><true/></BOOLEAN>"), iof.NewBuiltinIEId1(true))
    blt("builtin-integer", "020201f9", ie("BuiltinIE", 2, "<INTEGER>-7</INTEGER>"), iof.NewBuiltinIEId2(-7))
    blt("builtin-octets", "030403010203", ie("BuiltinIE", 3, "<OCTET_STRING>010203</OCTET_STRING>"),
        iof.NewBuiltinIEId3([]byte{1, 2, 3}))
    blt("builtin-printable", "0403024142", ie("BuiltinIE", 4, "<PrintableString>AB</PrintableString>"),
        iof.NewBuiltinIEId4("AB"))
    blt("builtin-utf8", "05040368c3a9", ie("BuiltinIE", 5, "<UTF8String>hé</UTF8String>"),
        iof.NewBuiltinIEId5("hé"))
    blt("builtin-bits", "060204a0", ie("BuiltinIE", 6, "<BIT_STRING>1010</BIT_STRING>"),
        iof.NewBuiltinIEId6(iof.BitString{Bytes: []byte{0xA0}, BitsUnused: 4}))
    // id 7 shares the BOOLEAN alternative with id 1
    blt("builtin-shared-alt", "070100", ie("BuiltinIE", 7, "<BOOLEAN><false/></BOOLEAN>"), iof.NewBuiltinIEId7(false))
    blt("builtin-named", "08010b", ie("BuiltinIE", 8, "<Small>11</Small>"), iof.NewBuiltinIEId8(11))
    return cs
}

func TestIocFormsRoundTrip(t *testing.T) {
    for _, c := range ifCases() {
        aper, err := c.enc()
        if err != nil {
            t.Errorf("%s: encode: %v", c.name, err)
            continue
        }
        if got := hex.EncodeToString(aper); got != c.aper {
            t.Errorf("%s: APER %s, want %s", c.name, got, c.aper)
        }
        if err := c.dec(aper); err != nil {
            t.Errorf("%s: decode % x: %v", c.name, aper, err)
        }
    }
}

func TestIocFormsCConverter(t *testing.T) {
    bin := converter(t)
    for _, c := range ifCases() {
        aper, err := c.enc()
        if err != nil {
            t.Errorf("%s: encode: %v", c.name, err)
            continue
        }
        if ref, ok := siConv(t, bin, c.siCase, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
            t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
        }
        if re, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
            t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
        }
        if xer, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oxer"); ok && bsXML(xer) != c.xer {
            t.Errorf("%s: C XER = %s, want %s", c.name, bsXML(xer), c.xer)
        }
    }
}

// The id and the selected alternative must agree, also for a built-in
// alternative shared by two ids.
func TestIocFormsIdMismatch(t *testing.T) {
    v := iof.NewBuiltinIEId2(1)
    v.Id = 1 // id 1 carries BOOLEAN, not INTEGER
    if _, err := v.Encode(); err == nil {
        t.Error("BuiltinIE id 1 with an INTEGER value encoded")
    }
    w := iof.NewInlineIEId1(3)
    w.Id = 7
    if _, err := w.Encode(); err == nil {
        t.Error("InlineIE id 7 with a Small value encoded")
    }
    // id 2 (INTEGER): open-type length 2, INTEGER length 1, -128
    if v, err := iof.DecodeBuiltinIE([]byte{0x02, 0x02, 0x01, 0x80}); err != nil {
        t.Errorf("DecodeBuiltinIE(02 02 01 80): %v", err)
    } else if v.Value.INTEGER == nil || *v.Value.INTEGER != -128 {
        t.Errorf("DecodeBuiltinIE(02 02 01 80) = %+v, want INTEGER -128", v.Value)
    }
    // a BOOLEAN payload under id 2 is not a valid INTEGER encoding
    if _, err := iof.DecodeBuiltinIE([]byte{0x02, 0x01, 0x80}); err == nil {
        t.Error("DecodeBuiltinIE(02 01 80) succeeded")
    }
}
