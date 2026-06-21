package main

// CBOR diagnostic notation parser (RFC 8949 §8 subset).
//
// The corpus uses a constrained subset:
//   - Top-level array of maps; map values may be any supported type.
//   - Maps with text-string or byte-string keys.
//   - Text strings ("..." with \" \\ \n escapes).
//   - Byte strings (h'<hex>' — no internal whitespace; case-insensitive).
//   - Integers (optional sign, decimal digits).
//   - Floats (decimal with point or exponent; keywords NaN, Infinity, -Infinity).
//   - Booleans (true, false) and null.
//
// Comments:
//   - Block: a line containing only "/" opens/closes a block; intervening lines are dropped.
//   - Whole-line "/.../" comments are dropped.
//   - In-band comments (mid-value) are NOT supported. The corpus does not use them.
//
// Output values:
//   - text string → string
//   - byte string → []byte
//   - integer    → int64
//   - float      → float64
//   - bool       → bool
//   - null       → nil
//   - array      → []interface{}
//   - map        → map[interface{}]interface{}
//
// These types round-trip through fxamacker/cbor's CoreDetEncOptions encoder
// to canonical ECF bytes, which is what build-fixture writes to disk.

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// StripDiagComments removes the line-based comment forms used by v1 corpus
// files plus the multi-line span comments used by v7.67 onward.
//
// The rules, applied per line outside string/byte-string literals:
//
//  1. A line whose trimmed content is exactly "/" toggles block mode
//     (top-of-file header convention). Inside a block every line is dropped.
//  2. A line whose trimmed content starts AND ends with "/" (length > 1) is
//     a whole-line comment; the line is dropped.
//  3. A line whose trimmed content starts with "/" but does NOT end with "/"
//     opens a multi-line span comment; all lines are dropped until a line
//     whose trimmed content ends with "/" closes it.
//
// Newlines are preserved on dropped lines so parse-error positions stay
// readable against the source.
func StripDiagComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	inBlock := false
	inSpan := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case inSpan:
			if strings.HasSuffix(trimmed, "/") {
				inSpan = false
			}
			out.WriteByte('\n')
		case inBlock:
			if trimmed == "/" {
				inBlock = false
			}
			out.WriteByte('\n')
		case trimmed == "/":
			inBlock = true
			out.WriteByte('\n')
		case len(trimmed) >= 2 && strings.HasPrefix(trimmed, "/") && strings.HasSuffix(trimmed, "/"):
			out.WriteByte('\n')
		case strings.HasPrefix(trimmed, "/"):
			inSpan = true
			out.WriteByte('\n')
		default:
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// ParseDiag parses a CBOR diagnostic notation string into a Go value tree.
// The top level must be a single value.
func ParseDiag(src string) (interface{}, error) {
	stripped := StripDiagComments(src)
	p := &diagParser{src: stripped}
	p.skipWS()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.src) {
		return nil, p.errf("trailing content after top-level value")
	}
	return v, nil
}

type diagParser struct {
	src string
	pos int
}

func (p *diagParser) errf(format string, args ...interface{}) error {
	line, col := 1, 1
	for i := 0; i < p.pos && i < len(p.src); i++ {
		if p.src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return fmt.Errorf("diag parse: line %d col %d: %s", line, col, fmt.Sprintf(format, args...))
}

func (p *diagParser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

func (p *diagParser) skipWS() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			p.pos++
			continue
		}
		break
	}
}

func (p *diagParser) consume(b byte) error {
	p.skipWS()
	if p.peek() != b {
		return p.errf("expected %q, got %q", b, p.peek())
	}
	p.pos++
	return nil
}

func (p *diagParser) hasPrefix(s string) bool {
	return strings.HasPrefix(p.src[p.pos:], s)
}

func (p *diagParser) parseValue() (interface{}, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, p.errf("unexpected end of input")
	}
	c := p.src[p.pos]
	switch {
	case c == '{':
		return p.parseMap()
	case c == '[':
		return p.parseArray()
	case c == '"':
		return p.parseTextString()
	case c == 'h' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '\'':
		return p.parseByteString()
	case c == 't' && p.hasPrefix("true"):
		p.pos += 4
		return true, nil
	case c == 'f' && p.hasPrefix("false"):
		p.pos += 5
		return false, nil
	case c == 'n' && p.hasPrefix("null"):
		p.pos += 4
		return nil, nil
	case c == 'N' && p.hasPrefix("NaN"):
		p.pos += 3
		return math.NaN(), nil
	case c == 'I' && p.hasPrefix("Infinity"):
		p.pos += 8
		return math.Inf(+1), nil
	case c == '-' && p.hasPrefix("-Infinity"):
		p.pos += 9
		return math.Inf(-1), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	}
	return nil, p.errf("unexpected char %q", c)
}

func (p *diagParser) parseMap() (interface{}, error) {
	if err := p.consume('{'); err != nil {
		return nil, err
	}
	out := make(map[interface{}]interface{})
	p.skipWS()
	if p.peek() == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWS()
		key, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if err := p.consume(':'); err != nil {
			return nil, err
		}
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		// Reduce []byte keys to a comparable form. map[interface{}]interface{}
		// requires keys to be comparable; []byte is not. Use a string of the
		// raw bytes (NOT hex) so the encoder still emits a CBOR byte string —
		// fxamacker/cbor treats interface{} keys that are []byte as bstr, but
		// since []byte itself is unhashable we have to wrap. We use a custom
		// marker type so the build step can dispatch correctly.
		if bs, ok := key.([]byte); ok {
			out[byteKey(string(bs))] = val
		} else {
			out[key] = val
		}
		p.skipWS()
		if p.peek() == ',' {
			p.pos++
			continue
		}
		if p.peek() == '}' {
			p.pos++
			return out, nil
		}
		return nil, p.errf("expected ',' or '}'")
	}
}

// byteKey is the marker type for byte-string map keys parsed out of the .diag.
// It is a string-backed type so it remains hashable (and thus usable as a Go
// map key), but it carries the semantic that the underlying bytes are a CBOR
// byte string, not a CBOR text string. The build-fixture encoder dispatches
// on this type to emit major type 2 instead of major type 3.
type byteKey string

func (p *diagParser) parseArray() (interface{}, error) {
	if err := p.consume('['); err != nil {
		return nil, err
	}
	var out []interface{}
	p.skipWS()
	if p.peek() == ']' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWS()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, val)
		p.skipWS()
		if p.peek() == ',' {
			p.pos++
			continue
		}
		if p.peek() == ']' {
			p.pos++
			return out, nil
		}
		return nil, p.errf("expected ',' or ']'")
	}
}

func (p *diagParser) parseTextString() (interface{}, error) {
	if err := p.consume('"'); err != nil {
		return nil, err
	}
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '"' {
			p.pos++
			return b.String(), nil
		}
		if c == '\\' {
			if p.pos+1 >= len(p.src) {
				return nil, p.errf("dangling escape")
			}
			esc := p.src[p.pos+1]
			switch esc {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '/':
				b.WriteByte('/')
			default:
				return nil, p.errf("unsupported escape %q", esc)
			}
			p.pos += 2
			continue
		}
		b.WriteByte(c)
		p.pos++
	}
	return nil, p.errf("unterminated text string")
}

func (p *diagParser) parseByteString() (interface{}, error) {
	// h'<hex>'
	if !p.hasPrefix("h'") {
		return nil, p.errf("expected h'...'")
	}
	p.pos += 2
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] != '\'' {
		p.pos++
	}
	if p.pos >= len(p.src) {
		return nil, p.errf("unterminated byte string")
	}
	raw := p.src[start:p.pos]
	p.pos++ // consume closing '

	// RFC 8949 §8 permits whitespace inside h'...'. The corpus does not, but
	// be lenient: strip whitespace before hex-decoding.
	var clean strings.Builder
	clean.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if !unicode.IsSpace(rune(raw[i])) {
			clean.WriteByte(raw[i])
		}
	}
	cleaned := clean.String()
	if len(cleaned)%2 != 0 {
		return nil, p.errf("odd-length hex in byte string")
	}
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, p.errf("invalid hex in byte string: %v", err)
	}
	return out, nil
}

func (p *diagParser) parseNumber() (interface{}, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}
	isFloat := false
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		isFloat = true
		p.pos++
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		isFloat = true
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
		}
	}
	lit := p.src[start:p.pos]
	if isFloat {
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil {
			return nil, p.errf("invalid float %q: %v", lit, err)
		}
		return f, nil
	}
	// Integer. Use int64; the corpus stays inside int64 range.
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return nil, p.errf("invalid integer %q: %v", lit, err)
	}
	return n, nil
}
