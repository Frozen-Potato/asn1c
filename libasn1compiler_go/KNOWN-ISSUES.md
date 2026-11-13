# Known issues

Known bugs and limitations of the Go backend. New issues are appended with the
next number; the Status column is updated when one is fixed.

Status: `Open`, `Fixed (<version>)`, `Wontfix`.

| # | Description | Status |
|---|-------------|--------|
| 1 | The C runtime cannot PER-encode a present value of `INTEGER (0..18446744073709551615)`: it keeps constraint bounds in a `long`, so even 0 fails ("aper encode failed"). `converter-example` fails identically, and the Go `Encode` returns the same error. Ranges that stay within `long` but exceed 32 bits (e.g. `0..1099511627775`) work. | Open (C runtime) |
| 2 | The generated C constraint check for an `INTEGER_t` beyond `long` uses `asn_INTEGER2long`, so values >= 2^63 are rejected ("value too large"); it also triggers a `-Wsign-compare` warning. | Open (C generator) |
| 3 | Type names that exist in several modules of one `-Fgo` run (the same name in two input files) make the generated conversion code refer to `struct <Name>` instead of the module-prefixed C name, so the cgo package fails to compile (`invalid application of 'sizeof' to incomplete type`). Workaround: give the types unique names. | Fixed (go.7) |
| 4 | A field of an inline `SEQUENCE` was checked for name collisions against the fields of the enclosing struct, so valid specifications (e.g. `examples/rrc-7.1.0.asn1`'s `completeSIB-List`) were refused. Output was never wrong. `rrc-7.1.0.asn1` now stops at #16. | Fixed (go.7) |
| 5 | `SEQUENCE OF` an inline unsigned `INTEGER` wider than 32 bits is not supported as an element (`INTEGER (0..4294967295)`): the C generator emits unusable C (`asn_DEF_Member_2` undeclared). | Fixed (go.7) |
| 6 | `SEQUENCE OF SEQUENCE OF {SEQUENCE \| CHOICE}` (and the `SET OF` forms): the C generator emitted unusable C. The Go backend handles the `SEQUENCE OF` forms; the `SET OF` forms are still refused by it (`SET OF` is not supported). | Fixed (go.7) |
| 7 | `SEQUENCE OF` a reference to a NULL type fails with `asn1cgo: conv: unresolved seqof elem`. | Fixed (go.7) |
| 8 | `SEQUENCE OF` with a `SIZE` constraint on both the outer and inner list makes asn1c abort in the parser (`asn1p_y.y` assertion). | Fixed (go.7) |
| 9 | `ISO646String` makes asn1c abort (`asn1fix_constraint_compat.c`, `asn1constraint_default_alphabet` assertion). | Open (asn1fix) |
| 10 | A top-level wide `INTEGER_t` leaf is always converted with the unsigned verbs, even when its Go type is `int64`. Only reachable with `-fwide-types`. | Open |
| 11 | An empty `PrintableString` (no `SIZE` lower bound) fails `Encode` with "value not given": the C constraint function rejects the NULL buffer an empty Go string produces. The other restricted string types allocate the buffer and are not affected. | Fixed (go.7) |
| 12 | A `DEFAULT` on a `BMPString` or `UniversalString` member is refused: the C generator stores the default as single-byte characters, not UCS-2 / UCS-4. | Wontfix (C generator) |
| 13 | The C time check accepts text after a well-formed `UTCTime` / `GeneralizedTime` (`"250102030405ZZ"`); the Go side does not parse or normalize time strings. | Open (C runtime) |
| 14 | `GeneralString`, `GraphicString`, `TeletexString`, `T61String` and `VideotexString` are written and read as hex in XER by the C runtime (it does not decode their character sets). The Go value is the raw bytes. | Open (C runtime) |
| 15 | The C runtime's XER decoder cannot read an empty `RELATIVE-OID` (`<x></x>`), although its XER encoder writes one; the APER of such a value round-trips. `converter-example -ixer` fails with "Input processing error". | Open (C runtime) |
| 16 | `examples/rrc-7.1.0.asn1` stopped at an enumerator name collision: in `SFN-SFN-Drift` the enumerators `sfnsfndrift5` and `sfnsfndrift-5` (and 13 more such pairs) both mapped to `SFNSFNDriftSfnsfndrift5`. Within one enumerator or named-bit list, a member that clashes with a sibling and has `_<digit>` in its C name now keeps that underscore (`D1` / `D_1`). | Fixed (go.8) |
| 17 | A `DEFAULT` on a `UTF8String`, `GeneralString`, `GraphicString`, `TeletexString`, `T61String`, `VideotexString`, `ObjectDescriptor`, `UTCTime` or `GeneralizedTime` member is refused. The C generator supports `DEFAULT` only on the known-multiplier string types (`IA5String`, `PrintableString`, `VisibleString`, `NumericString`; `BMPString` and `UniversalString` are refused, see #12), and its refusal message wrongly says that "character strings" in general do. To be handled together with #12. | Open (C generator) |
| 18 | The same hyphen clash on SEQUENCE fields, CHOICE alternatives and type names (`T ::= SEQUENCE { a1 BOOLEAN, a-1 BOOLEAN }`) is still refused with a collision. | Open |
| 19 | On a large specification (`examples/rrc-7.1.0.asn1`, about 4100 layout nodes) `asn1c -Fgo` ran for over ten minutes: the glue emitter and the package orderer searched all nodes, name rows or header files for every type, and appended to the generated files with a `strlen` of the whole file each time. The lookups are now indexed and the generated files are built in a length-tracking buffer; output is byte-identical and the run takes about 40 s. | Fixed (go.8) |
| 20 | With `-findirect-choice`, a member or alternative whose type is an alias of an alias (`PFL ::= Freq`, `pf PFL OPTIONAL`) was declared `struct PFL *pf;`, but no `struct PFL` exists (`PFL.h` has only `typedef Freq_t PFL_t;`): plain C code could not use the member, and the Go converters failed with `sizeof` of an incomplete type (`MBMS-PFLInfo ::= FrequencyInfo` in `rrc-7.1.0.asn1`). The C generator now names the constructed type the alias chain ends in (`struct Freq *pf;`). | Fixed (go.8) |
