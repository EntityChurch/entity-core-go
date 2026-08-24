package main

// The generator's PRNG — and why it is not math/rand.
//
// GUIDE-CONFORMANCE §7c.4(1) asks that each impl be able to RUN the seeded
// generator ("identical seed → identical shapes"), not merely replay the frozen
// output. The workbench harness that this generator is ported from uses Go's
// math/rand seeded at 20260716. That is correct for an intra-Go differential
// test and unusable for the cross-impl ask: math/rand's source is a Go-specific
// lagged-Fibonacci generator with a 607-word seeding ritual. Rust and Python
// cannot reproduce its stream, so "run the generator with seed S" means three
// different corpora in three languages.
//
// So the PRNG becomes part of the generator contract. SplitMix64 is the pick:
// it is six lines of wrapping 64-bit arithmetic with no state array, no
// warm-up, and no language-specific behavior, and it is already the standard
// seeding companion for xoshiro/xoroshiro — so an impl that wants it in Rust or
// Python writes it from this comment rather than hunting a dependency.
//
// The seed changes meaning as a result: it selects a stream in a NAMED
// algorithm rather than an unnamed one, so the corpus records `prng` beside
// `seed` and the sweep is NOT the same 300 shapes the workbench harness sees.
// That is intended. The workbench sweep proves Axis-1 == Stage-1 within Go; this
// corpus proves Go == Rust == Py at the boundary. Different claims, different
// coverage — §7c.4(4).
//
// Reference implementation for a porting impl (any 64-bit-wrapping language):
//
//	state += 0x9E3779B97F4A7C15
//	z = state
//	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
//	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
//	return z ^ (z >> 31)
//
// All arithmetic is mod 2^64; all shifts are logical.

const prngName = "splitmix64"

type rng struct {
	state uint64
}

func newRNG(seed uint64) *rng { return &rng{state: seed} }

// next returns the next 64-bit value in the stream.
func (r *rng) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0, n).
//
// Plain modulo, deliberately: rejection sampling would be the right call if
// this were sampling for statistical uniformity, but it is selecting among 3–8
// grammar alternatives, where the modulo bias is under one part in 2^61. What
// matters is that a porting impl reproduces the sequence exactly, and `next() %
// n` is unambiguous in every language. Rejection loops are where portable PRNG
// contracts usually diverge.
func (r *rng) intn(n int) int {
	if n <= 0 {
		panic("rng.intn: n must be positive")
	}
	return int(r.next() % uint64(n))
}
