package main

// Strict ECF decode for the decode_reject category. Returns
// (rejected, errorMessage). The v1 corpus exercises tag rejection
// (§6.3): any CBOR tag (major type 6) is non-canonical and MUST be
// rejected at decode time. Indefinite-length items are likewise
// forbidden by ECF §4.2.1 Rule 3.
//
// We use fxamacker/cbor's TagsMd=TagsForbidden + IndefLength=
// IndefLengthForbidden decoder against the canonical bytes. If the
// decoder errors, the bytes are rejected (good). If the decoder
// succeeds, the bytes were accepted (bad — this is a divergence the
// diff round will surface).

import (
	"github.com/fxamacker/cbor/v2"
)

func decodeReject(canonical []byte) (rejected bool, code string, errMsg string) {
	dm, err := cbor.DecOptions{
		TagsMd:      cbor.TagsForbidden,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		return false, "", "decoder setup: " + err.Error()
	}
	var v interface{}
	if err := dm.Unmarshal(canonical, &v); err != nil {
		// ECF non-canonicity — a CBOR tag on a data field (the v1 corpus's
		// tag_reject vectors) or an indefinite-length item — maps to the
		// spec's wire error code `400 non_canonical_ecf` (ENTITY-CBOR-
		// ENCODING §6.3 / §500, Appendix E §E.4). The raw decoder error is
		// kept separately for diagnostics. (All v1 decode_reject vectors are
		// tag-policy; future categories with their own codes would refine
		// this classification.)
		return true, codeNonCanonicalECF, err.Error()
	}
	return false, "", "decoder accepted non-canonical input"
}

// codeNonCanonicalECF is the spec wire error code for ECF non-canonicity
// rejection (ENTITY-CBOR-ENCODING §6.3 / §500).
const codeNonCanonicalECF = "non_canonical_ecf"
