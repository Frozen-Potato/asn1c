# Known issues

Known bugs and limitations of the Go backend. New issues are appended with the
next number; the Status column is updated when one is fixed.

Status: `Open`, `Fixed (<version>)`, `Wontfix`.

| # | Description | Status |
|---|-------------|--------|
| 1 | The C runtime cannot PER-encode a present value of `INTEGER (0..18446744073709551615)`: it keeps constraint bounds in a `long`, so even 0 fails ("aper encode failed"). `converter-example` fails identically, and the Go `Encode` returns the same error. Ranges that stay within `long` but exceed 32 bits (e.g. `0..1099511627775`) work. | Open (C runtime) |
| 2 | The generated C constraint check for an `INTEGER_t` beyond `long` uses `asn_INTEGER2long`, so values >= 2^63 are rejected ("value too large"); it also triggers a `-Wsign-compare` warning. | Open (C generator) |
| 3 | Type names that exist in several modules of one `-Fgo` run (the same name in two input files) make the generated conversion code refer to `struct <Name>` instead of the module-prefixed C name, so the cgo package fails to compile (`invalid application of 'sizeof' to incomplete type`). Workaround: give the types unique names. | Open |
| 4 | A field of an inline `SEQUENCE` was checked for name collisions against the fields of the enclosing struct, so valid specifications (e.g. `examples/rrc-7.1.0.asn1`'s `completeSIB-List`) were refused. Output was never wrong. `rrc-7.1.0.asn1` now stops at #16. | Fixed (go.7) |
| 5 | `SEQUENCE OF` an inline unsigned `INTEGER` wider than 32 bits is not supported as an element (`INTEGER (0..4294967295)`): the C generator emits unusable C (`asn_DEF_Member_2` undeclared). | Open (C generator) |
| 6 | `SEQUENCE OF SEQUENCE OF {SEQUENCE \| CHOICE}`: the C generator emits unusable C. | Open (C generator) |
| 7 | `SEQUENCE OF` a reference to a NULL type fails with `asn1cgo: conv: unresolved seqof elem`. | Open |
| 8 | `SEQUENCE OF` with a `SIZE` constraint on both the outer and inner list makes asn1c abort in the parser (`asn1p_y.y` assertion). | Open (parser) |
| 9 | `ISO646String` makes asn1c abort (`asn1fix_constraint_compat.c`, `asn1constraint_default_alphabet` assertion). | Open (asn1fix) |
| 10 | A top-level wide `INTEGER_t` leaf is always converted with the unsigned verbs, even when its Go type is `int64`. Only reachable with `-fwide-types`. | Open |
| 11 | An empty `PrintableString` (no `SIZE` lower bound) fails `Encode` with "value not given": the C constraint function rejects the NULL buffer an empty Go string produces. The other restricted string types allocate the buffer and are not affected. | Open |
| 12 | A `DEFAULT` on a `BMPString` or `UniversalString` member is refused: the C generator stores the default as single-byte characters, not UCS-2 / UCS-4. | Wontfix (C generator) |
| 13 | The C time check accepts text after a well-formed `UTCTime` / `GeneralizedTime` (`"250102030405ZZ"`); the Go side does not parse or normalize time strings. | Open (C runtime) |
| 14 | `GeneralString`, `GraphicString`, `TeletexString`, `T61String` and `VideotexString` are written and read as hex in XER by the C runtime (it does not decode their character sets). The Go value is the raw bytes. | Open (C runtime) |
| 15 | The C runtime's XER decoder cannot read an empty `RELATIVE-OID` (`<x></x>`), although its XER encoder writes one; the APER of such a value round-trips. `converter-example -ixer` fails with "Input processing error". | Open (C runtime) |
| 16 | `examples/rrc-7.1.0.asn1` stops at an enumerator name collision: in `SFN-SFN-Drift` (module `InformationElements`) the enumerators `sfnsfndrift5` and `sfnsfndrift-5` (and 13 more such pairs) both map to the Go constant `SFNSFNDriftSfnsfndrift5`. | Open |
