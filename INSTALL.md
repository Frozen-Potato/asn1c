
## Compiling From Sources

### Configure

See [REQUIREMENTS.md](REQUIREMENTS.md) for the complete list of dependencies.

Configure with the default settings:

    test -f configure || autoreconf -iv
    ./configure
    make

Configure with non-standard settings:

asn1c-specific ./configure options include:

  Option                 | Description
------------------------ | ---------------------------------------------------
  --enable-ASN_DEBUG     | produce debug log during `make check` testing
  --enable-code-coverage | whether to enable code coverage support
  --enable-Werror        | abort compilation after any C compiler warning
  --enable-test-Werror   | abort compiling tests after any C compiler warning
  --enable-test-32bit    | enable tests for 32-bit compatibility
  --disable-test-ubsan   | disable Undefined Behavior Sanitizer for tests
  --disable-test-asan    | disable Address Sanitizer for tests
  --enable-test-fuzzer   | enable LLVM LibFuzzer for randomized testing

invoke `./configure --help` for details.

### Build

Build the libraries and the compiler:

    make

Ensure asn1c is still behaving well after compiling on your platform:

    make check

### Install

Install the compiler into a standard location:

    make install
    # Use ./configure --prefix to override install location.

Display the `asn1c` manual page:

    man asn1c

### Windows (MSYS2, mingw-w64)

The compiler (`asn1c.exe`, `enber.exe`, `unber.exe`) builds as a native
64-bit Windows program with the mingw-w64 toolchain of
[MSYS2](https://www.msys2.org/). In an MSYS2 UCRT64 (or MINGW64) shell:

    pacman -S --needed make autoconf automake libtool bison flex diffutils \
        mingw-w64-ucrt-x86_64-gcc
    autoreconf -fi
    ./configure
    make

The repository carries a `.gitattributes` that fixes line endings to LF, so
a plain `git clone` is enough (if you set `core.autocrlf` to `true` yourself,
turn it off: the build scripts and the test data need LF). `asn1c.exe` writes
LF and copies the skeleton files byte for byte. Give `-S`, `-D` and `-Fgo=`
paths with `/` or `\`. Without `-S` the skeletons are looked for next to the
program (`../share/asn1c`, or `../skeletons` in a build tree).

The code asn1c generates compiles and runs with the same toolchain
(`gcc -std=gnu99 -D__USE_MINGW_ANSI_STDIO=1`, UCRT64 recommended). On
Windows `long` is 32 bits: a schema with constraint bounds, `DEFAULT` or
`ENUMERATED` values outside the 32-bit range is refused when its generated C
is compiled (`... needs a 64-bit long`); see KNOWN-ISSUES 76 in
`libasn1compiler_go/KNOWN-ISSUES.md`. The Go backend is not supported on
Windows (its output refuses to build); use WSL2 for that.

## Quick Usage Guide

For a usage guide and more information please refer to:

 * the [README.md](README.md) file
 * the asn1c manual page `man asn1c`
 * the included quick start PDF [doc/asn1c-quick.pdf](doc/asn1c-quick.pdf)
 * the comprehensive usage documentation [doc/asn1c-usage.pdf](doc/asn1c-usage.pdf)

In case of any difficulties with installing the compiler, consider using
the Online ASN.1 Compiler at http://lionet.info/asn1c.

-- 
Lev Walkin
vlm@lionet.info
