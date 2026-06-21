package types

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// TypeMultiGranter is the type name for system/capability/multi-granter.
const TypeMultiGranter = "system/capability/multi-granter"

// MultiGranter is the data shape for system/capability/multi-granter — the
// inline value carried in a multi-sig capability token's `granter` field.
//
// Each entry in Signers is an identity hash (content hash of a system/peer
// entity, V7 §1.5 / §3.5). Threshold (K) is how many of those signers must
// sign the cap for it to verify.
type MultiGranter struct {
	Signers   []hash.Hash `cbor:"signers"`
	Threshold uint64      `cbor:"threshold"`
}

// Validate enforces M3 structural constraints: N >= 2, K in [2, N], no
// duplicate signers. Used at chain-walk entry (MUST) and at content-store
// insertion (SHOULD).
func (mg MultiGranter) Validate() error {
	n := len(mg.Signers)
	if n < 2 {
		return fmt.Errorf("multi-granter: signers count %d < 2 (use single-sig form for N=1)", n)
	}
	if mg.Threshold < 2 {
		return fmt.Errorf("multi-granter: threshold %d < 2 (use single-sig form for K=1)", mg.Threshold)
	}
	if mg.Threshold > uint64(n) {
		return fmt.Errorf("multi-granter: threshold %d > signers count %d", mg.Threshold, n)
	}
	seen := make(map[hash.Hash]struct{}, n)
	for i, s := range mg.Signers {
		if _, dup := seen[s]; dup {
			return fmt.Errorf("multi-granter: duplicate signer at index %d", i)
		}
		seen[s] = struct{}{}
	}
	return nil
}

// HasSigner reports whether h is in mg.Signers.
func (mg MultiGranter) HasSigner(h hash.Hash) bool {
	for _, s := range mg.Signers {
		if s == h {
			return true
		}
	}
	return false
}

// Granter is the polymorphic value carried in CapabilityTokenData.Granter.
// It is either a single identity hash (single-sig, the historical shape) or
// a MultiGranter struct (multi-sig, root-only per M3).
//
// On the wire, the two shapes are distinguished by CBOR major type:
//   - bstr (major type 2) → single-sig identity hash
//   - map  (major type 5) → multi-granter struct
//
// CBOR tags on the granter field are forbidden (ENTITY-CBOR-ENCODING.md §11);
// UnmarshalCBOR rejects major type 6.
//
// Granter is intentionally not directly comparable with `==` because the
// multi-sig variant embeds a slice. Use the IsSingle/IsMulti accessors and
// EqualsHash helper.
type Granter struct {
	isMulti bool
	single  hash.Hash    // valid when isMulti == false
	multi   MultiGranter // valid when isMulti == true
}

// SingleSigGranter wraps an identity hash as a single-sig granter.
func SingleSigGranter(h hash.Hash) Granter {
	return Granter{single: h}
}

// MultiSigGranter wraps a MultiGranter as a multi-sig granter.
func MultiSigGranter(mg MultiGranter) Granter {
	return Granter{isMulti: true, multi: mg}
}

// IsMulti reports whether g is a multi-sig granter.
func (g Granter) IsMulti() bool { return g.isMulti }

// IsSingle reports whether g is a single-sig granter.
func (g Granter) IsSingle() bool { return !g.isMulti }

// SingleHash returns the wrapped identity hash. The bool is false when the
// granter is multi-sig.
func (g Granter) SingleHash() (hash.Hash, bool) {
	if g.isMulti {
		return hash.Hash{}, false
	}
	return g.single, true
}

// Multi returns the wrapped MultiGranter. The bool is false when the granter
// is single-sig.
func (g Granter) Multi() (MultiGranter, bool) {
	if !g.isMulti {
		return MultiGranter{}, false
	}
	return g.multi, true
}

// IsZero reports whether the granter is the zero value (no hash set, not
// multi-sig). Used in boundary checks like VerifyHandlerGrant. A multi-sig
// granter is never "zero" — even a malformed one carries its struct shape.
func (g Granter) IsZero() bool {
	if g.isMulti {
		return false
	}
	return g.single.IsZero()
}

// EqualsHash reports whether g is single-sig and its inner hash equals h.
// Multi-sig granters never equal a single hash.
func (g Granter) EqualsHash(h hash.Hash) bool {
	return !g.isMulti && g.single == h
}

// String returns a short description: the inner hash for single-sig, or
// "multi-sig(K-of-N)" for multi-sig.
func (g Granter) String() string {
	if g.isMulti {
		return fmt.Sprintf("multi-sig(%d-of-%d)", g.multi.Threshold, len(g.multi.Signers))
	}
	return g.single.String()
}

// Validate enforces structural constraints. Single-sig has none beyond the
// hash type itself; multi-sig delegates to MultiGranter.Validate (M3).
func (g Granter) Validate() error {
	if g.isMulti {
		return g.multi.Validate()
	}
	return nil
}

// MarshalCBOR encodes the granter using structural distinction (M8):
//   - single-sig → CBOR byte string (delegates to Hash.MarshalCBOR)
//   - multi-sig  → CBOR map with `signers` and `threshold`
//
// No CBOR tags are emitted (ENTITY-CBOR-ENCODING.md §11).
func (g Granter) MarshalCBOR() ([]byte, error) {
	if g.isMulti {
		return ecf.Encode(g.multi)
	}
	return g.single.MarshalCBOR()
}

// UnmarshalCBOR decodes by branching on CBOR major type. Major type 2 (bstr)
// is single-sig; major type 5 (map) is multi-sig. Major type 6 (tag) is
// rejected — tags on data fields are forbidden by ENTITY-CBOR-ENCODING.md §11.
func (g *Granter) UnmarshalCBOR(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("granter: empty CBOR data")
	}
	majorType := (data[0] >> 5) & 0x07
	switch majorType {
	case 2:
		var h hash.Hash
		if err := h.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("granter (single-sig): %w", err)
		}
		*g = Granter{single: h}
		return nil
	case 5:
		var mg MultiGranter
		if err := ecf.Decode(data, &mg); err != nil {
			return fmt.Errorf("granter (multi-sig): %w", err)
		}
		*g = Granter{isMulti: true, multi: mg}
		return nil
	case 6:
		return fmt.Errorf("granter: CBOR tags forbidden on data fields (ENTITY-CBOR-ENCODING.md §11)")
	default:
		return fmt.Errorf("granter: invalid CBOR major type %d (expected 2=bstr or 5=map)", majorType)
	}
}
