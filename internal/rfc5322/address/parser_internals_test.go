package address

import "testing"

func TestConsumeWord(t *testing.T) {
	cases := []struct {
		expected []Token
		input    []byte
	}{
		0: {
			expected: []Token{
				{
					Type: Atom,
					Data: []byte("AAA"),
				},
			},
			input: []byte("AAA"),
		},
		1: {
			expected: []Token{
				{
					Type: FWS,
					Data: []byte(" "),
				},
				{
					Type: Atom,
					Data: []byte("AAA"),
				},
				{
					Type: FWS,
					Data: []byte(" "),
				},
			},
			input: []byte(" AAA "),
		},
		2: {
			expected: []Token{
				{
					Type: FWS,
					Data: []byte("\r\n "),
				},
				{
					Type: Atom,
					Data: []byte("AAA"),
				},
				{
					Type: FWS,
					Data: []byte(" "),
				},
			},
			input: []byte("\r\n AAA "),
		},
		3: {
			expected: []Token{
				{
					Type: FWS,
					Data: []byte(" \r\n "),
				},
				{
					Type: Comment,
					Data: []byte("((COMMENT))"),
				},
				{
					Type: FWS,
					Data: []byte("\r\n "),
				},
				{
					Type: Atom,
					Data: []byte("AAA"),
				},
				{
					Type: FWS,
					Data: []byte(" "),
				},
			},
			input: []byte(" \r\n ((COMMENT))\r\n AAA "),
		},
	}
	for i, c := range cases {
		p := &addrParser{
			s: c.input,
		}
		ok, err := p.consumeWord()
		if err != nil {
			t.Log("Error:", err)
			t.Fail()
			continue
		}
		if len(c.expected) == 0 {
			if ok {
				t.Logf("#%d: expecting no tokens yielded, got %d", i, len(p.t))
				t.Fail()
				continue
			}
		} else {
			if !ok {
				if len(p.t) != 0 {
					t.Logf("#%d: %d tokens yielded, but the second value is false", i, len(p.t))
				} else {
					t.Logf("#%d: expecting tokens yielded, got none", i)
				}
				t.Fail()
				continue
			}
			if len(p.t) != len(c.expected) {
				t.Logf("#%d: expecting %d tokens, got %d", i, len(c.expected), len(p.t))
				for j, tok := range p.t {
					t.Logf("#%d: %d: %v", i, j, tok)
				}
				t.Fail()
				continue
			}
			for j, tok := range p.t {
				if tok.Type != c.expected[j].Type {
					t.Logf("#%d: expecting type %d, got %d", i, c.expected[j].Type, tok.Type)
					t.Fail()
				}
				if string(tok.Data) != string(c.expected[j].Data) {
					t.Logf("#%d: expecting data %q, got %q", i, c.expected[j].Data, tok.Data)
					t.Fail()
				}
			}
			if t.Failed() {
				break
			}
		}
	}
}

func TestTryConsumingPhrase(t *testing.T) {
	cases := []struct {
		expected []Token
		input    []byte
	}{
		{
			expected: []Token{
				{
					Type: Atom,
					Data: []byte("AAA"),
				},
				{
					Type: FWS,
					Data: []byte(" "),
				},
				{
					Type: Atom,
					Data: []byte("BBB"),
				},
				{
					Type: FWS,
					Data: []byte(" "),
				},
				{
					Type: Atom,
					Data: []byte("CCC"),
				},
			},
			input: []byte("AAA BBB CCC"),
		},
	}
	for _, c := range cases {
		p := &addrParser{
			s: c.input,
		}
		ok, err := p.tryConsumingPhrase()
		if err != nil {
			t.Log("Error:", err)
			t.Fail()
			continue
		}
		if len(c.expected) == 0 {
			if ok {
				t.Logf("Expecting no tokens yielded, got %d", len(p.t))
				t.Fail()
				continue
			}
		} else {
			if !ok {
				if len(p.t) != 0 {
					t.Logf("%d tokens yielded, but the second value is false", len(p.t))
				} else {
					t.Log("Expecting tokens yielded, got none")
				}
				t.Fail()
				continue
			}
			if len(p.t) != len(c.expected) {
				t.Logf("Expecting %d tokens, got %d", len(c.expected), len(p.t))
				t.Fail()
				continue
			}
			for i, tok := range p.t {
				if tok.Type != c.expected[i].Type {
					t.Logf("Expecting type %d, got %d", c.expected[i].Type, tok.Type)
					t.Fail()
					break
				}
				if string(tok.Data) != string(c.expected[i].Data) {
					t.Logf("Expecting data %q, got %q", c.expected[i].Data, tok.Data)
					t.Fail()
					break
				}
			}
		}
	}
}
