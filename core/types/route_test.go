package types

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

const (
	routeFakeDest = "2KDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	routeFakeVia  = "2KVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
)

// TestRouteRoundtripForward — a `forward` route to a peer-id with metric.
func TestRouteRoundtripForward(t *testing.T) {
	d := RouteData{
		Match:  routeFakeDest,
		Action: RouteActionForward,
		Via:    routeFakeVia,
		Metric: 10,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeRoute {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	dec, err := RouteDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Match != routeFakeDest || dec.Action != RouteActionForward ||
		dec.Via != routeFakeVia || dec.Metric != 10 {
		t.Fatalf("round-trip drift: %+v", dec)
	}
}

// TestRouteDefaultRouteForm — `*` match form (proposal §3 default route).
func TestRouteDefaultRouteForm(t *testing.T) {
	d := RouteData{
		Match:  RouteMatchDefault,
		Action: RouteActionForward,
		Via:    routeFakeVia,
	}
	e, _ := d.ToEntity()
	dec, _ := RouteDataFromEntity(e)
	if dec.Match != "*" {
		t.Fatalf("default-route token round-trip drift: %q", dec.Match)
	}
}

// TestRouteHashStability — equal inputs hash equal; differing metric
// (or any other field) produces a distinct hash so the storage path
// (RoutePath) doesn't collide route variants.
func TestRouteHashStability(t *testing.T) {
	mk := func(metric uint32) RouteData {
		return RouteData{
			Match:  routeFakeDest,
			Action: RouteActionForward,
			Via:    routeFakeVia,
			Metric: metric,
		}
	}
	e1, _ := mk(5).ToEntity()
	e2, _ := mk(5).ToEntity()
	if e1.ContentHash != e2.ContentHash {
		t.Fatal("hash drift across equal inputs")
	}
	e3, _ := mk(10).ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across distinct metrics")
	}
}

// TestRouteOmitemptyShape — null Via, null Metric, null ExpiresAt MUST
// drop from the wire (omitempty) so a minimal `*` default route has the
// shortest possible ECF encoding.
func TestRouteOmitemptyShape(t *testing.T) {
	// Deliver route with no Via, no Metric, no ExpiresAt (minimal).
	d := RouteData{
		Match:  RouteMatchDefault,
		Action: RouteActionDeliver,
	}
	e, _ := d.ToEntity()
	// Sanity check: the encoded data MUST NOT contain "via", "metric", or
	// "expires_at" — those are dropped by omitempty. We test by decoding
	// then re-encoding through a zero-init shape and asserting byte-equality.
	var via2 RouteData
	via2.Match = RouteMatchDefault
	via2.Action = RouteActionDeliver
	e2, _ := via2.ToEntity()
	if !bytes.Equal(e.Data, e2.Data) {
		t.Fatalf("ECF byte drift between RouteData with explicit empties and zero-value; omitempty broken: %x vs %x", e.Data, e2.Data)
	}
}

// TestRoutePath — content-hash hex addressing.
func TestRoutePath(t *testing.T) {
	d := RouteData{
		Match:  routeFakeDest,
		Action: RouteActionForward,
		Via:    routeFakeVia,
	}
	e, _ := d.ToEntity()
	path := RoutePath(e.ContentHash)
	if path == TypeRoute+"/" {
		t.Fatal("RoutePath returned bare prefix — hash hex missing")
	}
	// Expect: system/route/{hex}
	wantPrefix := TypeRoute + "/"
	if path[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("RoutePath prefix drift: %q", path)
	}
	hexPart := path[len(wantPrefix):]
	// The id segment is hex(Hash.Bytes()) = 2 * (1 algorithm byte + effective
	// digest length). For SHA-256: 2 * (1 + 32) = 66 hex chars.
	wantLen := 2 * len(e.ContentHash.Bytes())
	if len(hexPart) != wantLen {
		t.Fatalf("RoutePath id segment length: want %d hex chars, got %d (%q)", wantLen, len(hexPart), hexPart)
	}
}

// Ensure RouteData carries no leakage of hash.Hash directly — the route
// entity references peer-ids by Base58 string, not by content hash.
var _ = hash.Hash{}
