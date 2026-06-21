// Package chunker implements the chunking algorithms specified in
// EXTENSION-CONTENT v3.6 §3 — fixed-size (§3.2) and FastCDC (§3.6).
//
// The package is a pure function library — no handler dependency. Callers
// construct chunk and blob entities at a higher layer (see
// ext/content/builder.go).
package chunker

import (
	"crypto/sha256"
	"encoding/binary"
)

// GearTable is the FastCDC 256-entry 64-bit gear table per §3.6.1:
//
//	gear_table[i] = uint64_le(SHA-256("FastCDC" || byte(i))[0:8])
//
// All conforming implementations MUST derive the table this way. The table
// is computed once at package init.
var GearTable [256]uint64

func init() {
	for i := 0; i < 256; i++ {
		var buf [8]byte
		copy(buf[:], "FastCDC")
		buf[7] = byte(i)
		sum := sha256.Sum256(buf[:])
		GearTable[i] = binary.LittleEndian.Uint64(sum[0:8])
	}
}
