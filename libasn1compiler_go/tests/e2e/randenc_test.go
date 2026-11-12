// Randomized encode test: for every PDU type of the e2e modules (the list is
// generated into randreg_test.go by tests/run-e2e.sh from the Encode methods
// of the generated packages), build random valid-SHAPED values and Encode
// them. Shapes covered per type: every OPTIONAL present / every OPTIONAL
// absent / each OPTIONAL randomly present, every CHOICE alternative, and
// lists of length 1..3. The point is the arena accounting: a size pass that
// reserves fewer bytes than the fill consumes panics with "fixed-region
// undercounted" (and one that reserves more trips the exact-consumption
// check), which fails this test. Values need not satisfy every constraint:
// an rt.ErrConstraint (or any other returned error) is fine here, a PANIC is
// not; padalloc must additionally encode successfully for most values so the
// test cannot pass by only ever hitting a constraint error.
package e2e

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

type randPDU struct {
	name string
	typ  reflect.Type // the PDU struct type (not the pointer)
}

// randPDUs is filled by randreg_test.go (generated).
var randPDUs []randPDU

type randGen struct {
	rng  *rand.Rand
	mode int // 0: all OPTIONALs present, 1: all absent, else random
}

func isChoiceStruct(t reflect.Type) bool {
	if t.Kind() != reflect.Struct || t.NumField() < 2 {
		return false
	}
	f := t.Field(0)
	return f.Name == "Present" && f.Type.Kind() == reflect.Int32 &&
		strings.HasSuffix(f.Type.Name(), "Pr")
}

func (g *randGen) fill(v reflect.Value, depth int) {
	t := v.Type()
	switch t.Kind() {
	case reflect.Bool:
		v.SetBool(g.rng.Intn(2) == 0)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(g.rng.Intn(4)))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(g.rng.Intn(4)))
	case reflect.Float32, reflect.Float64:
		v.SetFloat([]float64{0, 1.5, -2}[g.rng.Intn(3)])
	case reflect.String:
		v.SetString(strings.Repeat("a", 1+g.rng.Intn(3)))
	case reflect.Ptr:
		present := g.mode == 0 || (g.mode != 1 && g.rng.Intn(2) == 0)
		if depth > 8 {
			present = false
		}
		if present {
			v.Set(reflect.New(t.Elem()))
			g.fill(v.Elem(), depth+1)
		}
	case reflect.Slice:
		n := 1 + g.rng.Intn(3)
		if depth > 8 {
			n = 0
		}
		v.Set(reflect.MakeSlice(t, n, n))
		for i := 0; i < n; i++ {
			g.fill(v.Index(i), depth+1)
		}
	case reflect.Struct:
		if t.Name() == "BitString" {
			n := 1 + g.rng.Intn(3)
			v.FieldByName("Bytes").SetBytes(make([]byte, n))
			return
		}
		if isChoiceStruct(t) {
			alt := 1 + g.rng.Intn(t.NumField()-1) // field i+1 is Present = i+1
			v.Field(0).SetInt(int64(alt))
			g.fill(v.Field(alt), depth+1)
			if v.Field(alt).Kind() == reflect.Ptr && v.Field(alt).IsNil() {
				v.Field(alt).Set(reflect.New(v.Field(alt).Type().Elem()))
				g.fill(v.Field(alt).Elem(), depth+1)
			}
			return
		}
		for i := 0; i < t.NumField(); i++ {
			if v.Field(i).CanSet() {
				g.fill(v.Field(i), depth+1)
			}
		}
	}
}

func encodeNoPanic(p any) (ok bool, panicMsg string) {
	defer func() {
		if r := recover(); r != nil {
			panicMsg = fmt.Sprint(r)
		}
	}()
	_, err := p.(interface{ Encode() ([]byte, error) }).Encode()
	return err == nil, ""
}

func TestRandomizedEncodeNoPanic(t *testing.T) {
	if len(randPDUs) == 0 {
		t.Fatal("randPDUs is empty: randreg_test.go was not generated")
	}
	const iters = 240
	for _, pdu := range randPDUs {
		okN := 0
		for it := 0; it < iters; it++ {
			g := &randGen{rng: rand.New(rand.NewSource(int64(it) + 1)), mode: it % 3}
			p := reflect.New(pdu.typ)
			g.fill(p.Elem(), 0)
			ok, pm := encodeNoPanic(p.Interface())
			if pm != "" {
				t.Errorf("%s: iteration %d (mode %d): Encode panicked: %s", pdu.name, it, it%3, pm)
				break
			}
			if ok {
				okN++
			}
		}
		t.Logf("%-45s %3d/%d encoded", pdu.name, okN, iters)
		if strings.HasPrefix(pdu.name, "padalloc.") && okN < iters/8 {
			t.Errorf("%s: only %d/%d random values encoded; the test is not reaching the allocator", pdu.name, okN, iters)
		}
	}
}
