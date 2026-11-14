// Aliases of a CHOICE (tests/e2e/choice.asn, built with
// -findirect-choice). C has only `typedef Orig_t Alias_t;`, so the generated
// converters of Alias, Alias2, RichA and RichA2 must spell the target's
// Orig_PR enum and Orig__t2 struct tags: building this module is the first
// check (C used to reject Alias_PR and struct Alias__t2).
//
// The C descriptor of such an alias carries no PER codec, so Wrap and L (the
// PDUs holding the aliases) cannot be APER-encoded, by Go or by the C
// converter alike; they are compared as XER instead: the XER the generated
// glue prints for each value must equal the C converter's XER of the same
// document. Copied into the aliaschoice package directory by
// tests/run-e2e.sh (the XER entry points are unexported).
package aliaschoice

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var gap = regexp.MustCompile(`>\s+<`)

// norm drops the layout whitespace (the glue prints canonical XER, the
// converter indented XER with spaced hex octets).
func norm(b []byte) string {
	return strings.ReplaceAll(gap.ReplaceAllString(strings.TrimSpace(string(b)), "><"), " ", "")
}

// cXER feeds doc through the C converter (XER in, XER out).
func cXER(t *testing.T, pdu, doc string) string {
	t.Helper()
	bin := os.Getenv("ASN1CGO_C_CONVERTER")
	if bin == "" {
		t.Skip("ASN1CGO_C_CONVERTER not set")
	}
	f := filepath.Join(t.TempDir(), "in.xml")
	if err := os.WriteFile(f, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-ixer", "-oxer", "-p", pdu, f).CombinedOutput()
	if err != nil {
		t.Fatalf("converter %s: %v\n%s", pdu, err, out)
	}
	return norm(out)
}

func TestAliasChoiceXER(t *testing.T) {
	i31, i5, i3, i2 := int64(31), int64(5), int64(3), int64(2)
	yes, no := true, false
	ints := RichL{0, 9, 4}

	wraps := []struct {
		w   Wrap
		doc string
	}{
		{Wrap{
			O: Orig{Present: OrigPrT1, T1: &i31},
			R: Rich{Present: RichPrA, A: &yes},
			S: Sq{A: 2, Inl: SqInl{X: 7, Y: &yes}, C: SqC{Present: SqCPrV, V: &no}},
		}, `<Wrap><o><t1>31</t1></o><r><a><true/></a></r><s><a>2</a><inl><x>7</x><y><true/></y></inl><c><v><false/></v></c></s></Wrap>`},
		{Wrap{
			O: Orig{Present: OrigPrT2, T2: &OrigT2{P1: 23}},
			R: Rich{Present: RichPrN, N: &RichN{Present: RichNPrU, U: &i2}},
			S: Sq{A: 0, Inl: SqInl{X: 0}, C: SqC{Present: SqCPrU, U: &i3}},
		}, `<Wrap><o><t2><p1>23</p1></t2></o><r><n><u>2</u></n></r><s><a>0</a><inl><x>0</x></inl><c><u>3</u></c></s></Wrap>`},
		{Wrap{
			O: Orig{Present: OrigPrT2, T2: &OrigT2{P1: 7, P2: &i3}},
			R: Rich{Present: RichPrL, L: &ints},
			S: Sq{A: 3, Inl: SqInl{X: 1}, C: SqC{Present: SqCPrV, V: &yes}},
		}, `<Wrap><o><t2><p1>7</p1><p2>3</p2></t2></o><r><l><INTEGER>0</INTEGER><INTEGER>9</INTEGER><INTEGER>4</INTEGER></l></r><s><a>3</a><inl><x>1</x></inl><c><v><true/></v></c></s></Wrap>`},
		{Wrap{
			O: Orig{Present: OrigPrT1, T1: &i5},
			R: Rich{Present: RichPrS, S: &RichS{Q: RichSQ{Z: 3}, W: []byte{0xde, 0xad}}},
			S: Sq{A: 1, Inl: SqInl{X: 4}, C: SqC{Present: SqCPrU, U: &i2}},
		}, `<Wrap><o><t1>5</t1></o><r><s><q><z>3</z></q><w>DEAD</w></s></r><s><a>1</a><inl><x>4</x></inl><c><u>2</u></c></s></Wrap>`},
	}
	for _, c := range wraps {
		got, err := xerWrap(&c.w)
		if err != nil {
			t.Errorf("%s: %v", c.doc, err)
			continue
		}
		if want := cXER(t, "Wrap", c.doc); norm(got) != want {
			t.Errorf("Wrap XER\n got %s\nwant %s", norm(got), want)
		}
	}

	// the list of Alias: every alternative of Orig
	l := L{
		{Present: OrigPrT1, T1: &i31},
		{Present: OrigPrT2, T2: &OrigT2{P1: 23}},
		{Present: OrigPrT2, T2: &OrigT2{P1: 7, P2: &i3}},
	}
	got, err := xerL(&l)
	if err != nil {
		t.Fatalf("L: %v", err)
	}
	// the C converter must parse what the glue printed and print it back
	// unchanged
	if want := cXER(t, "L", string(got)); norm(got) != want {
		t.Errorf("L XER\n got %s\nwant %s", norm(got), want)
	}
	for _, frag := range []string{"<t1>31</t1>", "<p1>23</p1>", "<p2>3</p2>"} {
		if !strings.Contains(string(got), frag) {
			t.Errorf("L XER %s lacks %s", norm(got), frag)
		}
	}
}
