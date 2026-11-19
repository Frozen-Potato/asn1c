// Types written directly in information objects (tests/e2e/iocinline.asn):
// constrained, constructed and ENUMERATED types, a type written twice, a
// NULL, and a named type whose name exists in two modules. Copied into the generated
// module by tests/run-e2e.sh together with seqof_test.go (siCase helpers),
// bits_test.go (bsXML) and default_test.go (the C converter).
//
// Per case: the exact APER bytes (X.691, worked out by hand), Go's decode
// gives the value back, and the C converter agrees (XER -> APER, APER
// re-encode, APER -> XER). The XER element of each value is the type's
// X.693 name (INTEGER, OCTET_STRING, SEQUENCE_OF, ...).
package e2e

import (
    "bytes"
    "encoding/hex"
    "testing"

    iil "asn1cgo.test/go/iocinline"
)

type iiCase struct {
    siCase
    aper string // hex
}

func iiCases() []iiCase {
    var cs []iiCase
    add := func(name, aper, alt string, id int64, v iil.CellIE) {
        xer := "<CellIE><id>" + itoa(id) + "</id><value>" + alt + "</value></CellIE>"
        cs = append(cs, iiCase{siMk(name, "CellIE", xer, &v, iil.DecodeCellIE), aper})
    }
    tr, f := true, false
    y := int64(3)

    // a named type whose name exists in two modules (C: IocInline_Twin)
    add("twin", "010180", "<Twin><true/></Twin>", 1, iil.NewCellIEId1(true))
    // constrained built-in types: PER uses the constraint (3 bits, a
    // fixed-size unaligned octet pair, a 3-bit length, a fixed-size bit field)
    add("int-0-7", "0201a0", "<INTEGER>5</INTEGER>", 2, iil.NewCellIEId2(5))
    add("octets-2", "0302abcd", "<OCTET_STRING>ABCD</OCTET_STRING>", 3,
        iil.NewCellIEId3([]byte{0xAB, 0xCD}))
    add("printable", "0403204869", "<PrintableString>Hi</PrintableString>", 4,
        iil.NewCellIEId4("Hi"))
    add("bits-4", "0501a0", "<BIT_STRING>1010</BIT_STRING>", 5,
        iil.NewCellIEId5(iil.BitString{Bytes: []byte{0xA0}, BitsUnused: 4}))
    add("enum", "060140", "<ENUMERATED><green/></ENUMERATED>", 6,
        iil.NewCellIEId6(iil.CellIEValueENUMERATEDRedGreenBlueGreen))
    // constructed types, tagged by the module's AUTOMATIC TAGS (the SET is
    // encoded in p, q order)
    add("choice-x", "070140", "<CHOICE><x><true/></x></CHOICE>", 7,
        iil.NewCellIEId7(iil.CellIEValueCHOICEXBOOLEANYINTEGER03{
            Present: iil.CellIEValueCHOICEXBOOLEANYINTEGER03PrX, X: &tr}))
    add("choice-y", "0701e0", "<CHOICE><y>3</y></CHOICE>", 7,
        iil.NewCellIEId7(iil.CellIEValueCHOICEXBOOLEANYINTEGER03{
            Present: iil.CellIEValueCHOICEXBOOLEANYINTEGER03PrY, Y: &y}))
    add("set", "0801cc", "<SET><p>9</p><q><true/></q></SET>", 8,
        iil.NewCellIEId8(iil.CellIEValueSETPINTEGER09QBOOLEANOPTIONAL{P: 9, Q: &tr}))
    add("set-absent", "080100", "<SET><p>0</p></SET>", 8,
        iil.NewCellIEId8(iil.CellIEValueSETPINTEGER09QBOOLEANOPTIONAL{P: 0}))
    add("sequence", "090355e680", "<SEQUENCE><s><b><false/></b></s><t>ABCD</t></SEQUENCE>", 9,
        iil.NewCellIEId9(iil.CellIEValueSEQUENCESSEQUENCEBBOOLEANTOCTETSTRINGSIZE2{
            S: iil.CellIEValueSEQUENCESSEQUENCEBBOOLEANTOCTETSTRINGSIZE2S{B: f},
            T: []byte{0xAB, 0xCD}}))
    add("sequence-of", "0a014f",
        "<SEQUENCE_OF><SEQUENCE><k>1</k></SEQUENCE><SEQUENCE><k>7</k></SEQUENCE></SEQUENCE_OF>", 10,
        iil.NewCellIEId10(iil.CellIEValueSEQUENCESIZE14OFSEQUENCEKINTEGER07{{K: 1}, {K: 7}}))
    // id 11 writes the same type as id 9: one shared alternative
    add("shared", "0b03808100", "<SEQUENCE><s><b><true/></b></s><t>0102</t></SEQUENCE>", 11,
        iil.NewCellIEId11(iil.CellIEValueSEQUENCESSEQUENCEBBOOLEANTOCTETSTRINGSIZE2{
            S: iil.CellIEValueSEQUENCESSEQUENCEBBOOLEANTOCTETSTRINGSIZE2S{B: tr},
            T: []byte{1, 2}}))
    // a NULL: no payload, the constructor takes no value; an empty open
    // type value is one zero octet (X.691 11.2.1)
    add("null", "0c0100", "<NULL></NULL>", 12, iil.NewCellIEId12())
    return cs
}

func TestIocInlineRoundTrip(t *testing.T) {
    for _, c := range iiCases() {
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

func TestIocInlineCConverter(t *testing.T) {
    bin := converter(t)
    for _, c := range iiCases() {
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

// Values outside the written type's constraints are refused, as for a named
// type.
func TestIocInlineConstraints(t *testing.T) {
    bad := map[string]iil.CellIE{
        "int 8":        iil.NewCellIEId2(8),
        "octets len 1": iil.NewCellIEId3([]byte{1}),
        "printable 0":  iil.NewCellIEId4(""),
        "bits 3":       iil.NewCellIEId5(iil.BitString{Bytes: []byte{0xA0}, BitsUnused: 5}),
        "enum 5":       iil.NewCellIEId6(iil.CellIEValueENUMERATEDRedGreenBlue(5)),
        "set p 10":     iil.NewCellIEId8(iil.CellIEValueSETPINTEGER09QBOOLEANOPTIONAL{P: 10}),
        "seqof empty":  iil.NewCellIEId10(iil.CellIEValueSEQUENCESIZE14OFSEQUENCEKINTEGER07{}),
    }
    for name, v := range bad {
        if _, err := v.Encode(); err == nil {
            t.Errorf("%s: encoded", name)
        }
    }
    // the decoder reads the 3-bit form of INTEGER (0..7): 0xa0 is 5
    v, err := iil.DecodeCellIE([]byte{0x02, 0x01, 0xa0})
    if err != nil || v.Value.INTEGER07 == nil || *v.Value.INTEGER07 != 5 {
        t.Errorf("DecodeCellIE(02 01 a0) = %+v, %v; want INTEGER 5", v, err)
    }
}
