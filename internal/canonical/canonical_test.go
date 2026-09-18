package canonical

import (
	"strings"
	"testing"
)

func TestKeyOrderingAndWhitespace(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{ "a" : [ 1 , 2 ] , "b" : { "x" : true } }`, `{"a":[1,2],"b":{"x":true}}`},
		// Keys compared as UTF-16 code units: U+00E9 ("é") sorts before many
		// CJK characters but after ASCII.
		{`{"é":1,"a":2}`, `{"a":2,"é":1}`},
	}
	for _, c := range cases {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("Parse(%s): %v", c.in, err)
		}
		got, err := Encode(v)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if string(got) != c.want {
			t.Errorf("Parse/Encode:\n got %s\nwant %s", got, c.want)
		}
	}
}

func TestNumberNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"123", "123"},
		{"-0", "0"},
		{"100000000000000000000000", "100000000000000000000000"}, // big integer preserved
		{"1.50", "1.5"},
		{"1e3", "1000"},
		{"0.000001", "0.000001"},
		{"123456789.1234568", "123456789.1234568"}, // shortest round-trip
		{"2.5E-2", "0.025"},
	}
	for _, c := range cases {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("Parse(%s): %v", c.in, err)
		}
		got, err := Encode(v)
		if err != nil {
			t.Fatalf("Encode(%s): %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("number %s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestRejectInvalidDocuments(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,  // duplicate keys
		`{"v":NaN}`,      // NaN
		`{"v":Infinity}`, // Infinity
		`{"a":1} extra`,  // trailing data
		`{"v":01}`,       // leading zero integer
	}
	for _, in := range bad {
		v, err := Parse([]byte(in))
		if err == nil {
			if _, encErr := Encode(v); encErr == nil {
				t.Errorf("expected rejection for %s", in)
			}
		}
	}
}

func TestStringEscaping(t *testing.T) {
	got, err := Encode("é\t\n\x01")
	if err != nil {
		t.Fatal(err)
	}
	want := "\"é\\t\\n\\u0001\""
	if string(got) != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestOrderIndependence(t *testing.T) {
	a, _ := Encode(mustParse(t, `{"z":[1,{"y":2,"x":3}],"a":"s"}`))
	b, _ := Encode(mustParse(t, `{ "a":"s", "z": [1, {"x":3,"y":2}] }`))
	if string(a) != string(b) {
		t.Fatalf("encodings differ:\n%s\n%s", a, b)
	}
	if !strings.HasPrefix(string(a), `{"a":"s","z":[1,{"x":3,"y":2}]}`) {
		t.Fatalf("unexpected canonical form: %s", a)
	}
}

func mustParse(t *testing.T, in string) any {
	t.Helper()
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
