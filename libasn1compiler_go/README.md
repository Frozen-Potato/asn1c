# libasn1compiler_go — the asn1c Go backend

This directory adds a Go code generator to the pinned asn1c fork. It runs
inside the same `asn1c` binary, after the C pass, over the same resolved
AST — the Go output always reflects exactly what the C backend saw
(`EM_INDIRECT` recursion markers included).

The backend is spec-agnostic: it generates Go from whatever ASN.1 the
caller names on the command line, within the supported construct set
(see Platform and limits). It builds and generates with no repository or
harness outside this fork.

Documentation here is for users of `-Fgo`. For the generated code's error
model see the runtime module's README (`rt/go/README.md`, shipped in every
release as the module's `README.md`; see Runtime module below).

## Build

```sh
autoreconf -fi && ./configure CC=gcc 'CFLAGS=-O1 -g' && make
```

Output binary: `asn1c/asn1c`. Hook surface: `asn1c/asn1c.c` (flag parse +
one dispatch call) and `asn1c/Makefile.am` (sources include) — the stock
asn1c sources are otherwise untouched.

## Generating Go

```sh
asn1c -S <fork>/skeletons -fincludes-quoted -fcompound-names \
      -findirect-choice -fno-include-deps -gen-PER -no-gen-OER -pdu=auto \
      -D <c-outdir> -Fgo=<go-outdir> <spec.asn...>
```

`-no-gen-OER` is the supported configuration. When OER is off the generator
writes `-DASN_DISABLE_OER_SUPPORT` into the `#cgo CFLAGS` lines of the
generated cgo files, and the runtime module defines it by default, so no
`CGO_CFLAGS` is needed. Trees generated with OER on (omit `-no-gen-OER`) also
build and work for APER without any tag. `-tags asn1cgo_oer` only compiles the
runtime's OER codec in; the generated Go API is APER-only, so it matters only
if you call the C OER functions yourself.

**Module path.** The Go module path is
`<ASN1CGO_GO_MODULE_PREFIX>/<basename of the -Fgo dir>`; with no prefix it is
just the basename. `-Fgo=out/go` with prefix `your.prefix` yields module
`your.prefix/go`, and packages are imported as `your.prefix/go/<package>`.

Without a prefix the basename must not be a standard-library top-level path
element (`go`, `net`, `crypto`, `math`, `os`, `testing`, ... — the first path
elements of `go list std`, minus `vendor`/`internal` — or the reserved
patterns `std`, `cmd`, `all`): a module named `go` would import its packages
as `go/<package>`, inside the standard library tree, and `go build` fails.
asn1c refuses it before writing anything (exit 70, `-D` untouched):
`asn1cgo: go module path 'go' collides with the Go standard library; set
ASN1CGO_GO_MODULE_PREFIX or rename the -Fgo directory`. With a prefix the
module path's first element contains a dot, so no basename collides.
`tests/run-stdlib-names.sh` checks the generator's table against the local
`go list std`.

**Workspace layout.** The generated `go.mod` sets `go 1.21.0` and requires
the runtime module (see Runtime module) at the generator's embedded version.
By default that is all: Go fetches the runtime. With `ASN1CGO_RT_LOCAL=<dir>`
it also has `replace <rt> => <dir>`. When `-Fgo` has a parent
directory component (e.g. `out/go`), the generator also writes a `go.work`
in that parent (`out/`) listing the generated module (and, in local mode, the
`ASN1CGO_RT_LOCAL` dir), creating it if absent and otherwise adding the entries to its `use ( … )`
block (each entry once; entries whose directory is gone are pruned). It is
rewritten atomically and only after the whole tree was generated, so a failed
run never modifies it and a rerun never adds a duplicate `use` line. Concurrent
generators into sibling `-Fgo` dirs under one parent are serialised with an
exclusive `flock(2)` on `<parent>/.go.work.lock` (a separate file, created if
absent and left in place), held from before `go.work` is read until after it is
written and across the tree swap, so no `use` entry is lost and no sibling is
pruned while it is renamed aside. `flock` is advisory (it only coordinates
asn1c processes) and may be unreliable or a no-op on some network filesystems;
keep the parent on a local filesystem when generating in parallel. If the lock
cannot be taken, generation fails and the tree is left unchanged. A bare
`-Fgo=gen` has no parent component, so no `go.work` is written and the
`replace` does the work.

Go 1.21 or newer is required (cgo enabled). The e2e test can be run against
the floor with `GOTOOLCHAIN=go1.21.13 sh libasn1compiler_go/tests/run-e2e.sh`.

**All-or-nothing output.** The Go tree is generated into a staging directory
next to the target (`<parent>/.<basename>.asn1cgo-tmp-XXXXXX`, same
filesystem) and only swapped into place when every stage succeeded:

- target absent: the staging dir is renamed to `<dir>`;
- target present: it is renamed aside to `<parent>/.<basename>.asn1cgo-old-XXXXXX`,
  the staging dir is renamed to `<dir>`, then the old tree is deleted (if the
  second rename or the `go.work` update fails, the old tree is renamed back).

On any failure the staging dir is removed, `<dir>` is left exactly as it was,
and asn1c prints `asn1cgo: …: <path>: <reason>` lines to stderr plus a final
`asn1cgo: Go generation failed; <dir> left unchanged` and exits 70. A `-Fgo`
path that exists but is not a directory is refused.

**Not atomic across the C and Go outputs.** `asn1c` writes the C code
straight into `-D` (stock behaviour) before the Go pass runs. Rejects that do
not depend on the C pass run first, as a pre-flight, so those leave `-D`
untouched and exit 70 with `no C output was written`: the construct rejects
(unsupported DEFAULT forms, `[[ ]]` version brackets, unsupported types such as SET /
SET OF / OID, a DEFAULT of a named-bit BIT STRING, unresolvable references) an invalid `-Fgo` basename or `ASN1CGO_GO_MODULE_PREFIX`, and (without a prefix) a `-Fgo` basename that is a standard-library top-level name.
The remaining Go-pass failures can only be detected after the C pass, because
the name pass reads the `EM_INDIRECT` / `EM_UNRECURSE` markers it stamps: Go
name collisions, by-value type cycles, and I/O errors while writing the Go tree.
In that case `-D` holds the **new** C code while the Go tree (including its
`internal/cspec` copy of the C sources) is still the **previous** generation.
asn1c says so on stderr; fix the error and regenerate both together, and do not
build the old Go tree against the new C output.

Because `<dir>` is **replaced as a whole**, every regeneration removes files
that are no longer produced (a renamed type leaves no stale `.c`/`.h`
behind), and **anything you keep inside `<dir>` is deleted** — do not put
hand-written files there (keep them in a separate package/module that
imports the generated one). The `-D <c-outdir>` C output is written by the C
pass *before* the Go pass starts and is not part of this scheme: when the Go
pass fails (exit 70), the C files in `-D` have already been updated while the
`-Fgo` tree is unchanged. If asn1c is killed by a signal, a hidden
`.<basename>.asn1cgo-tmp-*` directory may remain next to `<dir>`; it is safe
to delete.

`-Fgo=<dir>` emits the Go module rooted at `<dir>`: `go.mod`, one Go
package per ASN.1 module (`<module>_dir`, lowercased, `-`→`_`), the C
conversion tree under `<dir>/internal/cspec/`, Flat-C layout headers and
asserts under `<dir>/c/`, and the `Encode`/`Decode` public API per PDU
type in each package.

Every generated `.go` file opens with the standard line

```go
// Code generated by asn1cgo. DO NOT EDIT.
```

before the build tag and package clause, so Go tooling recognizes and
skips the files.

Run every asn1c invocation through `exec -a asn1c` (or a binary named
`asn1c`): asn1c stamps its command line into every generated file, and a
stable argv keeps output reproducible.

The generator emits unformatted-but-valid Go. Run `gofmt -w` over the
output tree as a separate pipeline step and fail on `gofmt -l` dirt.

## Using the generated code

For each PDU type the generated package exports exactly:

```go
func (p *<PDU>) Encode() ([]byte, error)   // APER bytes
func Decode<PDU>(b []byte) (*<PDU>, error) // APER bytes -> value
```

The example module used throughout this section (a SEQUENCE, a nested
CHOICE, an OPTIONAL member — no imports, no object classes):

```asn.1
Synth-Example DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

Example-PDU ::= SEQUENCE {
    requestId   INTEGER (0..65535),
    payload     Example-Payload,
    note        PrintableString (SIZE(1..32)) OPTIONAL,
    ...
}

Example-Payload ::= CHOICE {
    text        PrintableString (SIZE(1..32)),
    number      INTEGER (0..255),
    ...
}

END
```

Generating it yields, among the tree, the package `synth_example` with

```go
type ExamplePDU struct {
    RequestId int64
    Payload   ExamplePayload
    Note      *string          // OPTIONAL: nil = absent
}
type ExamplePayload struct {
    Present ExamplePayloadPr   // discriminant
    Text    *string
    Number  *int64
}
```

and round-tripping a value is (with `-Fgo=<dir>/go` and
`ASN1CGO_GO_MODULE_PREFIX=your.prefix`; the import path follows the module
path rule above):

```go readme-example
package main

import (
    "fmt"

    ex "your.prefix/go/synth_example"
)

func main() {
    v := &ex.ExamplePDU{
        RequestId: 7,
        Payload: ex.ExamplePayload{
            Present: ex.ExamplePayloadPrNumber,
            Number:  ptrTo(int64(42)),
        },
    }
    wire, err := v.Encode()
    if err != nil {
        panic(err)
    }
    back, err := ex.DecodeExamplePDU(wire)
    if err != nil {
        panic(err)
    }
    fmt.Println(back.RequestId, *back.Payload.Number)
}

func ptrTo[T any](v T) *T { return &v }
```

(`ptrTo` is a helper for the snippet only; generated packages take no
position on one.) Every value is an ordinary Go struct tree: slices,
pointers for OPTIONAL/CHOICE members, no handle types, nothing to free
after use.

**DEFAULT members.** A SEQUENCE member marked `DEFAULT` is supported when
the C generator emits `default_value_cmp`/`default_value_set` for it (one
shared predicate decides both, so the two can never disagree):

- BOOLEAN, INTEGER and ENUMERATED with a plain integer / `TRUE` / `FALSE` /
  enumerator-identifier value (including INTEGER types stored as `INTEGER_t`,
  and references to such types);
- the character string type this backend supports (PrintableString) with a
  quoted-string value;
- OCTET STRING with an `'..'H` / `'..'B` value that is a whole number of
  octets, and BIT STRING (no named bits) with an `'..'H` / `'..'B` value.

Anything else (REAL, NULL, SEQUENCE / CHOICE / SEQUENCE OF values, named-bit
BIT STRING, values given in other forms, ...) fails generation before the C
pass with `asn1cgo: DEFAULT member <Type>.<member> is out of model in module
<M>: <reason>` and exit 70, because the C generator would silently treat such
a member as OPTIONAL.

A DEFAULT member is a **plain value** in the Go struct, never a pointer:

```go
type DefaultsPDU struct {
    Flag  bool       // BOOLEAN DEFAULT TRUE
    Small int64      // INTEGER (0..7) DEFAULT 0
    Name  string     // PrintableString DEFAULT "hi"
    Octs  []byte     // OCTET STRING DEFAULT 'AB'H
    Bits  BitString  // BIT STRING DEFAULT '101'B
}
```

- `Decode` always yields the effective value: an absent member (or an absent
  extension addition) comes back holding its DEFAULT, filled in by the C
  runtime.
- `Encode` always hands the value to the C codec, which leaves out a root
  member that equals its DEFAULT (presence bit 0). Go never distinguishes
  "absent" from "equal to the default".
- **The Go zero value is not the DEFAULT.** `T{}` gives `false` / `0` / `""` /
  `nil`, even where the DEFAULT is `TRUE`, `5` or `"hi"`, and `Encode` sends
  exactly what the field holds. Set DEFAULT fields explicitly. For this the
  generator emits the DEFAULT of every such member as an exported
  declaration next to the struct: a typed `const` named
  `<StructGoName><FieldGoName>Default` (`DefaultsPDUFlagDefault`, typed with
  the field's own type, so an ENUMERATED member gets its enum type), or a
  `var` for slice / struct valued types (OCTET STRING, BIT STRING). Do not
  modify those vars. The names take part in the generator's usual
  package-level collision check, so a clash with another generated name
  fails generation.
- A member equal to its DEFAULT is omitted from the encoding, in both the
  root and the extension additions (an extension bit is set only when some
  addition differs from its DEFAULT); a missing member decodes to its DEFAULT.

**Error handling** is uniform across every generated package: failures
are `*rt.Error` values matching `errors.Is` against the sentinels —
see the runtime module's README (`rt/go/README.md`).

**Which codes occur where.**

| Code | Encode | Decode |
|------|--------|--------|
| `ErrArg` | nil receiver | **nil or empty input** (`Decode(nil)`, `Decode([]byte{})`) |
| `ErrAlloc` | yes (see the encoder-OOM note below) | yes |
| `ErrConstraint` | value outside a declared range/size/alphabet | decoded value violates a constraint |
| `ErrEncode` | the APER encoder failed | never |
| `ErrDecode` | never | malformed bytes, including an IE id the spec's object set does not list |
| `ErrTrailing` | never | bytes left after the PDU |
| `ErrChoiceNothing`, `ErrChoiceBad` | a CHOICE with no / an invalid `Present` | defensive only (the codec never yields these) |
| `ErrIOCUnknown` | the IE id is not in the governing object set | defensive only; an unknown id is rejected earlier as `ErrDecode` |
| `ErrIOCMismatch` | the id is known, but the value's `Present` is not the alternative that id governs | defensive only |
| `ErrDepth` | recursion budget exceeded | recursion budget exceeded |
| `ErrInternal` | a bug in the generator or runtime | same |

`ErrInternal` is never caused by caller input: it means a generator
invariant was violated at run time. Please report it, with the spec.

On encode, the IE id is checked against the object set first
(`ErrIOCUnknown`); only a known id is then compared with the selected
alternative (`ErrIOCMismatch`).

**Encoder out-of-memory is reported as `ErrEncode`.** If asn1c's own
encoder runs out of memory while producing the output buffer, the
failure surfaces as `ErrEncode`, not `ErrAlloc`: the encoder reports
only that it failed. `ErrAlloc` covers the allocations made by the
generated conversion code and the runtime arena, including Encode's
backing block (plain `malloc`, NULL on failure — not cgo's aborting
`C.malloc`) and a block size that overflows `uintptr` or does not fit an
`int`; Encode returns it before any further cgo call.

**IE constructors (specs with IOC-governed IE lists only).** Some
protocol families — 3GPP-style ones in particular — dispatch
information elements through an Information Object Class and an object
set: the IE list is a SEQUENCE OF records whose `id` selects the value
type from the object-set row. For such a spec the generated package
additionally emits **one constructor per object-set row**, so the caller
supplies only the IE payload and the record's dispatch fields are
filled from the spec row itself.

Naming rule: `New` + R2(X) + R2(I), where X is the record type's Go
name, I is the asn1c C identifier of the row's ID value reference, and
R2 is the generator's identifier-casing rule. Illustratively, a row
`{ ID id-example-id … TYPE Example-Type … }` in a record type
`Example-IEs` yields

```go
func NewExampleIEsIdExampleID(v ExampleType) ExampleIEs
```

which returns the record with every dispatch field the object class
declares — the id, the value union's `Present`, and any further
row-governed field the class defines — filled from the spec row. A spec
without object sets gets no constructors at all (build such struct
values directly).

All record fields are plain data: `Encode` writes whatever each field
holds (the constructor's spec values unless you change them), and
`Decode` returns every field as received, without checking it against
the spec.

**Recursion depth.** Encode and decode charge a budget of 64 depth
units per call: one unit per entry into a recursive type's conversion,
so a recursive ASN.1 level nested through several types typically costs
several units. Past the bound the call fails with an error that matches
`errors.Is(err, rt.ErrDepth)`; the value is rejected rather than
allowed to overflow the stack. The bound is compile-time: 64 is
`ASN1CGO_MAX_DEPTH` in the runtime's `rt/err.h`, mirrored by the
`maxEncodeDepth` constant the generator writes into every package — to
change it, edit the rt header and regenerate the trees (a regenerated
package and the rt module it was built against must come from the same
value).

### Named-bit BIT STRING

`BIT STRING { a(0), b(3) }` is the same Go value as a plain BIT STRING
(`BitString`, `*BitString` when optional; a named type is `type X BitString`).
The names only add `int` bit-position constants, in declaration order, named
like the constants of an ENUMERATED in the same position
(`<GoType><Bit>`; `<Parent><Member><Bit>` for an inline member, `<Choice><Alt><Bit>`
for a CHOICE alternative):

```go
// bit positions of Caps
const (
	CapsC int = 7
	CapsA int = 0
	CapsB int = 3
)
```

They are package-level names and collide like every other generated name. Set
a bit with `bs.Bytes[n/8] |= 0x80 >> (n % 8)`. The C APER encoder writes the
bits as given; the UPER encoder drops trailing zero bits and pads up to the
SIZE lower bound. A DEFAULT of a named-bit type is refused.

### SEQUENCE OF with an inline element type

`SEQUENCE OF` works whether the element is a type reference or an inline
(anonymous) type. The C backend calls an inline element `Member`
(`struct T__Member`, `A_SEQUENCE_OF(long)`, ...); Go follows the same name:

| ASN.1 element | Go |
|---|---|
| INTEGER, BOOLEAN, REAL, OCTET STRING, BIT STRING, PrintableString | the unnamed leaf mapping: `[]int64`, `[]bool`, `[]float64`, `[][]byte`, `[]BitString`, `[]string` |
| NULL | `[]struct{}` (the NULL leaf mapping, `struct{}`; one entry per NULL) |
| named-bit BIT STRING | `[]BitString`, plus the bit constants `<Owner>Member<Bit>` |
| ENUMERATED | `type <Owner>Member int32` and its value constants |
| SEQUENCE, CHOICE | `type <Owner>Member struct {...}` (a CHOICE with its `Pr` type and constants) |
| SEQUENCE OF | `type <Owner>Member []Elem`, recursively |

`<Owner>` is the name the enclosing position gets: the type for a top-level
`T ::= SEQUENCE OF ...` (`TMember`), `<Type><Member>` for a SEQUENCE member or
CHOICE alternative `a` of `T` (`TAMember`), and `<Owner>Member` again for an
element of an element (`TMemberMember`). The name is registered like every other
generated name, so `TMember ::= BOOLEAN` next to an inline element of `T`
fails with a collision. A SEQUENCE OF alternative of a CHOICE is
`type <Choice><Alt> []Elem`, held through a pointer like every alternative.

Not supported (the C generator itself emits unusable C for them):
`SEQUENCE OF SEQUENCE OF {SEQUENCE | CHOICE}` and an inline unsigned INTEGER
wider than `long` (`INTEGER (0..4294967295)`) as an element.

## Runtime module

Generated code imports the runtime module (error model + arena + the asn1c
skeleton codec), whose source is `libasn1compiler_go/rt/go` in this
repository:

- **Module path:** `github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go` (package import path `github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt`).
  `ASN1CGO_GO_MODULE_PREFIX` does not affect it; it only prefixes the
  generated modules.
- **Fetch (default).** The generated `go.mod` contains
  `require github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go v0.3.1` and nothing else about the runtime; `go.work`
  lists only the generated modules. Go downloads the runtime from the
  public repository, so no copy of the runtime is needed. The generator
  cannot compute the module hash offline, so run **once** after
  generation (it needs network access or a `GOPROXY`):

  ```sh
  cd out/go && go mod tidy
  ```

  which writes `go.sum`. Until then `go build` stops with the ordinary
  `missing go.sum entry for module providing package github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt …`. Commit
  `go.sum`; re-run `go mod tidy` only when the runtime version changes.
  (Regenerating rewrites `go.mod` but not `go.sum`.) `tests/run-rt-fetch.sh`
  exercises this flow against a `file://` `GOPROXY` without network.
- **Local (offline / development).** Set `ASN1CGO_RT_LOCAL=<dir>`, a
  checkout of the runtime (a directory whose `go.mod` declares
  `module github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go`, i.e. `<fork>/libasn1compiler_go/rt/go`). The generator
  checks this before writing anything (exit 70 otherwise) and adds
  `replace github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go => <dir>` to `go.mod` — relative to the `-Fgo` dir when `<dir>`
  lies inside the `-Fgo` dir's parent (e.g. `../rt`), absolute otherwise —
  and lists `<dir>` in `go.work`. No `go.sum` entry is needed for a
  replaced module.
- **Release procedure.** The runtime is versioned in lockstep with the
  generator: `ASN1CGO_RT_VERSION` in `go_entry.c` is the version every
  generated `go.mod` requires. To release: bump it (and the version
  text in `rt/go/README.md`), commit, then tag that commit with the
  module-path-relative tag and push it:

  ```sh
  git tag libasn1compiler_go/rt/go/v0.3.1 <commit>
  git push origin libasn1compiler_go/rt/go/v0.3.1
  ```

  A generated tree is only fetchable once that tag exists; before it,
  use local mode. The skeleton files in `rt/go/rt` are copies of
  `skeletons/`; refresh them with `libasn1compiler_go/rt/sync-skeletons.sh`
  after changing the skeletons.
- **Installed asn1c.** `make install` puts the rt C files the generator
  copies into every tree in `<pkgdatadir>/go-rt`; with the default `-S`
  directory no `ASN1CGO_RT_SRC` is needed.

**Upgrading from the dotless `asn1cgo-rt` (runtime v0.2.x).** v0.3.0 is
a breaking change: the module path changed from `asn1cgo-rt` (or
`<prefix>/asn1cgo-rt`) to `github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go`.

1. Regenerate every tree with the new `asn1c`; the `go.mod` now requires
   the new path (the old `replace … => ../asn1cgo-rt` is gone) and the
   imports use `github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt`.
2. Update hand-written imports of the old `…/asn1cgo-rt/rt` path to
   `github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt`.
3. Run `go mod tidy` in each generated dir (fetch mode), or set
   `ASN1CGO_RT_LOCAL` (local mode). The `../asn1cgo-rt` copy beside the
   generated dirs is no longer used; delete it. An existing `go.work`
   that still lists `./asn1cgo-rt` keeps working: the entry is kept
   while that directory exists and pruned by the next run once it is
   gone (you may also just delete the line). Delete a stale `go.sum`
   line for the old module if you have one.
4. Do not publish the runtime under your own prefix any more; that
   workflow was removed.

## Environment variables

| Variable | Effect |
|---|---|
| `ASN1C_DESTDIR` | Optional override. By default the Go pass reads the C tree from the `-D` directory (`.` when absent) and copies it into `<go-outdir>/internal/cspec`; when set, this names the source of that copy instead. |
| `ASN1C_PREFIX` | Per-run C symbol prefix (e.g. `EX_`). Prefixed runs keep Go names prefix-free (namespacing is per Go package). |
| `ASN1CGO_FORK_SKEL` | Optional override of the skeletons directory (default: the `-S` path). The skeletons dir also locates this module's runtime source: `<parent>/libasn1compiler_go/rt/go/rt`. |
| `ASN1CGO_RT_LOCAL` | Directory of a runtime checkout (`go.mod` must declare the rt module path; else exit 70). Adds `replace <rt> => <dir>` to the generated `go.mod` and lists `<dir>` in `go.work`. Unset: fetch mode (see Runtime module). |
| `ASN1CGO_RT_SRC` | Override for the runtime source directory (defaults to `<fork>/libasn1compiler_go/rt/go/rt`, then `<skeletons>/go-rt` when installed). Every generated tree carries copies of these rt files. |
| `ASN1CGO_GO_MODULE_PREFIX` | Module path prefix. Set: each spec module becomes `<prefix>/<basename>` with prefixed imports. Unset: bare-basename module paths. Does not affect the runtime module path. |
| `ASN1CGO_DUMP_NAMES` | Write the identifier name rows (owning module, kind, C id, Go name) to the named file. |
| `ASN1CGO_DUMP_COVERAGE` | Write the per-kind construct coverage tally to the named file. |
| `ASN1CGO_DUMP_CHOICE_ALTS` | Print the running maximum CHOICE alternative/extension-index counts seen. |
| `ASN1CGO_FLATDBG` | Trace the Flat layout engine. |

## Platform and limits

- **amd64-only**: the Flat C layout model mirrors the x86-64 SysV ABI;
  every generated `.go` file carries `//go:build amd64`.
- **Recursion depth**: bounded at 64 depth units per encode/decode
  (`ASN1CGO_MAX_DEPTH` in the rt error header).
- **C-side stack budget**: each decode runs asn1c's `asn_decode` with a
  stack guard of `ASN1CGO_C_STACK_MAX` bytes (default 98304 = 96 KiB, rt
  error header; override with `-DASN1CGO_C_STACK_MAX=<bytes>`, nonzero),
  so a hostile deeply nested input is rejected during C decoding instead of
  being fully materialised and exhausting the thread stack. Measured at
  gcc -O2: 64 depth units cost about 16–17 KB (68 units about 17.7 KB), so
  the default leaves over 5x headroom and input within
  `ASN1CGO_MAX_DEPTH` never trips it. The guard's failure is an ordinary
  `RC_FAIL` from asn1c, indistinguishable from malformed input, so it
  surfaces as `ErrDecode` (not `ErrDepth`); `ErrDepth` is reported for
  trees that decode within the budget but exceed 64 units. Lower the budget
  for small thread stacks (musl: 128 KiB), but not below the measured need
  of your deepest recursive type.
- **`[[ ]]` extension-addition groups**: rejected at generation (the
  post-parse AST cannot distinguish them from plain members).
- **`DEFAULT` members**: supported for exactly the members the C generator
  emits default callbacks for (see "DEFAULT members" under "Using the
  generated code"); every other DEFAULT form is rejected at generation (out
  of model).
- **String types**: the string kinds this backend supports only (e.g.
  PrintableString); other string kinds are rejected at generation with
  the type, member and construct named.
- **Fork runtime fixes**: the skeletons in this fork carry two aPER
  fragmentation fixes vs upstream — the OCTET STRING 16K-chunk terminator
  handling and the open-type (IE value) encoder's zero-length terminator
  after a full final 16K fragment. Wires that exercise these boundaries
  round-trip byte-identically on this fork's runtime and fail decode on an
  unfixed one.
  They also carry fixes for aPER SEQUENCE DEFAULT handling (the aPER encoder
  passed the member slot instead of the member to `default_value_cmp` and
  tested its result inverted, so it dropped every DEFAULT member regardless
  of value; the aPER decoder filled absent extension-addition defaults from
  the wrong member table). Without them DEFAULT members do not survive an
  aPER round trip.

**Tests.** `tests/run-e2e.sh` generates Go from `tests/e2e/ex.asn` and
`tests/e2e/ioc.asn` (plus `default.asn` and `nsmall.asn`) with the built `asn1c/asn1c`, builds it with cgo (no
manual `CGO_CFLAGS`) and runs `tests/e2e/main_test.go`: an APER round-trip
check plus one negative test per error code reachable from caller input
(the unreachable codes are listed at the top of that file), once with
`-no-gen-OER` and once with OER enabled. It also runs
`tests/e2e/faults_test.go` with `-tags asn1cgo_faults`, an allocation-fault
sweep that fails each runtime allocation in turn (Encode's backing block
included) and requires `ErrAlloc`
and a zero `ArenaBalance`. `tests/e2e/nsmall_test.go` covers "normally small"
values >= 64 (a SEQUENCE with 70 extension additions, a CHOICE with 70
extension alternatives, an ENUMERATED with 70 extension values): APER
round-trips at indices 0, 63, 64, 65, 69, hand-computed APER/UPER bytes for
index 64, truncated and zero-count inputs, and the C converter's APER/UPER/XER
(mirrors C `check-164`). `tests/run-c-invariance.sh` checks that adding
`-Fgo=` leaves the generated C byte-identical (apart from the stamped
command line). `tests/e2e/seqofinline.asn` and `seqofinline_test.go` cover
SEQUENCE OF with inline element types (APER and XER round trips against the C
converter, an empty list and one at the SIZE bound, the `-race` detector and
the allocation-fault sweep). `tests/run-feature-matrix.sh` generates every
`tests/feature-matrix/*.asn` (module `Probe`), runs `go vet` on the output and
compares the outcome with `expected.tsv`: `OK` (generates and vets), `REFUSED`
(a clean `asn1cgo: <construct> in module ...` refusal, whose text is also
matched) or `KNOWN-BROKEN <task>` (reported as XFAIL; the run fails when one
starts to pass). No case may end in an internal error (`asn1cgo: conv:`,
`glue:`, `flat:`, `ctor:`) or generate Go or C that fails `go vet`. All the
scripts exit 77 (skip) when a prerequisite (`go`, cgo,
linux/amd64, or the built `asn1c`) is unavailable.
