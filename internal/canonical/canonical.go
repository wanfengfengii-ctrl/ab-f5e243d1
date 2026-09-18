// Package canonical implements the deterministic JSON normalization used for
// payloads, signing envelopes and digests.
//
// The rules are a self-contained subset of RFC 8785 (JSON Canonicalization
// Scheme):
//
//   - Object members are emitted in ascending lexicographic order of their keys
//     where keys are compared as UTF-16 code unit sequences (shorter sequence
//     is a prefix tie-breaker), exactly like JCS.
//   - No insignificant whitespace is emitted.
//   - Strings use the minimal JSON escaping: ", \ and the control characters
//     U+0000..U+001F are escaped (with the short forms \b \t \n \f \r); all
//     other Unicode code points are emitted as UTF-8 directly.
//   - Null, true and false are emitted as such.
//   - Integer numbers (tokens without an exponent matching -?(0|[1-9][0-9]*))
//     are emitted verbatim, with -0 normalized to 0, preserving arbitrary
//     precision.
//   - All other finite numbers are parsed as IEEE-754 binary64 and emitted as
//     the shortest fixed-point decimal string that round-trips
//     (strconv.FormatFloat with -1 bits in 'f' format). Exponential tokens are
//     accepted and normalized the same way; integer-valued floats with
//     magnitude >= 10^21 are rejected because fixed-point expansion would be
//     ambiguous about precision. NaN and +-Infinity are not valid JSON.
//
// Duplicate object member names are rejected at parse time.
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Object is a JSON object with members preserved in input order until Encode
// sorts them deterministically.
type Object struct {
	Members []Member
}

// Member is one Object entry.
type Member struct {
	Key   string
	Value any
}

// Parse parses a single JSON document into canonical value types. Objects
// become *Object and numbers become json.Number. Duplicate keys, invalid UTF-8
// and trailing data are rejected.
func Parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("canonical: trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("canonical: empty JSON document")
		}
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &Object{}
			seen := make(map[string]struct{})
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("canonical: invalid object key")
				}
				if _, dup := seen[key]; dup {
					return nil, fmt.Errorf("canonical: duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj.Members = append(obj.Members, Member{Key: key, Value: val})
			}
			if _, err := dec.Token(); err != nil { // closing }
				return nil, err
			}
			return obj, nil
		case '[':
			arr := make([]any, 0)
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // closing ]
				return nil, err
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("canonical: unexpected delimiter %q", t)
		}
	case string:
		return t, nil
	case json.Number:
		return t, nil
	case bool:
		return t, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("canonical: unsupported token %T", tok)
	}
}

// Encode serializes a value produced by Parse (or built from *Object, []any,
// string, json.Number, bool and nil) into canonical bytes.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MustEncode panics on error; intended for constants built by the server.
func MustEncode(v any) []byte {
	b, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func writeValue(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t)
	case json.Number:
		s, err := normalizeNumber(string(t))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case *Object:
		return writeObject(b, t)
	case Object:
		return writeObject(b, &t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		return fmt.Errorf("canonical: cannot encode type %T", v)
	}
	return nil
}

func writeObject(b *bytes.Buffer, obj *Object) error {
	members := make([]Member, len(obj.Members))
	copy(members, obj.Members)
	// JCS key ordering: compare UTF-16 code units.
	for i := 1; i < len(members); i++ {
		for j := i; j > 0 && keyLess(members[j].Key, members[j-1].Key); j-- {
			members[j], members[j-1] = members[j-1], members[j]
		}
	}
	b.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, m.Key)
		b.WriteByte(':')
		if err := writeValue(b, m.Value); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func keyLess(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Parse already rejects invalid UTF-8, but never emit replacement chars silently.
			r = 0xFFFD
			size = 1
		}
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				b.WriteString("\\u00")
				b.WriteByte(hex[(r>>4)&0xF])
				b.WriteByte(hex[r&0xF])
			} else {
				b.WriteString(s[i : i+size])
			}
		}
		i += size
	}
	b.WriteByte('"')
}

var integerRe = func() func(string) bool {
	// Hand-rolled to avoid pulling a regexp into the hot path.
	return func(s string) bool {
		if s == "" {
			return false
		}
		i := 0
		if s[0] == '-' {
			if len(s) == 1 {
				return false
			}
			i = 1
		}
		if s[i] == '0' {
			return len(s) == i+1
		}
		if s[i] < '1' || s[i] > '9' {
			return false
		}
		for i++; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
}()

func normalizeNumber(raw string) (string, error) {
	if integerRe(raw) {
		if raw == "-0" {
			return "0", nil
		}
		return raw, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "", fmt.Errorf("canonical: invalid number %q", raw)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("canonical: non-finite number %q", raw)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	// Reject integer-valued floats whose fixed-point expansion hides precision.
	if math.Trunc(f) == f {
		abs := math.Abs(f)
		if abs >= 1e21 {
			return "", fmt.Errorf("canonical: integer-valued number outside safe range: %q", raw)
		}
	}
	// FormatFloat 'f' -1 may still emit exponent in tiny cases? 'f' never does.
	return s, nil
}
