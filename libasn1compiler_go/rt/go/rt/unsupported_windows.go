//go:build windows

package rt

/*
#error "asn1cgo: the Go backend is not supported on Windows: the generated Go code and this module need LP64 (C long is 8 bytes), Windows is LLP64 (long is 4 bytes). Use WSL2 or Linux (amd64 or arm64)."
*/
import "C"
