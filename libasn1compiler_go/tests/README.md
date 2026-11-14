# Go backend tests

Each `run-*.sh` exits 0 on pass and 77 when skipped (no `go`, no cgo, ...).

| script | checks |
| --- | --- |
| `run-e2e.sh` | Generates Go and C from `e2e/*.asn`, builds with cgo, runs `go test` (APER/UPER/XER round-trips against the C converter, every reachable error code, race runs, an allocation-fault sweep), twice: with and without OER. Also runs the `cycle/`, `oneway/`, unsupported-DEFAULT and stdlib-collision cases, and calls `run-stdlib-names.sh`, `run-rt-fetch.sh` and `run-rt-skeleton-sync.sh`. |
| `run-feature-matrix.sh` | Generates every `feature-matrix/*.asn` and vets the output; each case must match its row in `feature-matrix/expected.tsv`. |
| `run-c-invariance.sh` | Adding `-Fgo` must not change the C that asn1c writes. |
| `run-gowork-race.sh` | Parallel generators into sibling `-Fgo` dirs all end up in the shared `go.work`. |
| `run-rt-fetch.sh` | Fetch mode of the runtime module against a `file://` GOPROXY. |
| `run-rt-skeleton-sync.sh` | `rt/go/rt` C files equal `skeletons/` and compile warning-free. |
| `run-stdlib-names.sh` | The stdlib name table in `go_names.c` matches `go list std`. |

## e2e layout

`e2e/` holds topic files: `<topic>.asn` (one or more modules; every module
name is unique across the directory) with `<topic>_test.go` next to it.
`run-e2e.sh` passes all `.asn` files to one asn1c run, copies the `_test.go`
files into the generated module, and generates `randreg_test.go` so
`randenc_test.go` covers every PDU type. Files `*_internal_test.go` are copied
into one generated package instead (they test unexported helpers).

Topics: `xmod` (imports across modules), `set` (SET, SET OF), `choice`,
`names` (hyphen / shadowed names), `seqof` (SEQUENCE OF shapes), `bits`
(BIT STRING); the rest are single-purpose (`default`, `nsmall`, `strings`,
`oids`, `extgroup`, `extwide`, `inlconstr`, `padalloc`, `ex`, `ioc`).

## feature matrix layout

`feature-matrix/` has two kinds of file, plus `expected.tsv` (one row per
file: `OK`, `REFUSED <message substring>` or `KNOWN-BROKEN <note>`):

- **Family files** `fam-*.asn` (`fam-sof`, `fam-str`, `fam-inl`, `fam-set`,
  `fam-oid`, ...), one `OK` module each, holding many cases. Every case starts
  with a `-- <case-name>` comment, and its types carry the case name in
  CamelCase: `T` of `sof-int-mem` is `SofIntMem`, its helper `U` is
  `SofIntMemU`. `fam-set-expl` is its own file because it uses
  `EXPLICIT TAGS`; `fam-xmod` holds `ModA` / `ModB` with imports.
- **Single-case files** (`<case>.asn`, module `Probe`): every `REFUSED` and
  `KNOWN-BROKEN` case (a refusal stops the whole module, so it cannot share a
  file), and the `OK` cases whose point is how names interact across the
  module (`type-hyphen`, `value-hyphen`, `ioc-hyphen`).

A family row is as strong as its weakest case: if any case in the family stops
generating or vetting, the whole row fails, and the failing construct is in the
asn1c / go vet message.

## Adding a test

Add to the matching topic file (e2e) or family file (matrix). Create a new
file only for a new topic, and add it to `run-e2e.sh` (both the asn1c list
and the copied `_test.go` list) and to git.

Matrix: a case that must generate (`OK`) goes into its family file, under a
`-- <case-name>` comment, with every type renamed to carry the case name
(`SofIntMem`, `SofIntMemU`); the construct itself stays as it was. No
`expected.tsv` change is needed. A case that must be refused, or is known
broken, gets its own `feature-matrix/<case>.asn` (module `Probe`) and a row in
`expected.tsv`. A new family needs a `fam-<name> OK` row.
