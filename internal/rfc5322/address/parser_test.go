// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package address

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestAddressParsingError(t *testing.T) {
	mustErrTestCases := [...]struct {
		text        string
		wantErrText string
	}{
		0:  {"a@gmail.com b@gmail.com", "expected single address"},
		1:  {"\"\x00\" <null@example.net>", "bad character in quoted-string"},
		2:  {"\"\\\x00\" <escaped-null@example.net>", "bad character in quoted-string"},
		3:  {"John Doe", "no angle-addr"},
		4:  {`<jdoe#machine.example>`, "missing @ in addr-spec"},
		5:  {`John <middle> Doe <jdoe@machine.example>`, "missing @ in addr-spec"},
		6:  {"cfws@example.com (", "misformatted parenthetical comment"},
		7:  {"empty group: ;", "no angle-addr"},
		8:  {"root group: embed group: null@example.com;", "no angle-addr"},
		9:  {"group not closed: null@example.com", "missing ; in group"},
		10: {"group: first@example.com, second@example.com;", "group with multiple addresses"},
		11: {"john.doe", "missing '@' or angle-addr"},
		12: {"john.doe@", "missing '@' or angle-addr"},
		13: {"John Doe@foo.bar", "no angle-addr"},
		14: {" group: null@example.com; (asd", "misformatted parenthetical comment"},
		15: {" group: ; (asd", "no angle-addr"},
		16: {"<jdoe@[[192.168.0.1]>", "bad character in domain-literal"},
		17: {"<jdoe@[192.168.0.1>", "unclosed domain-literal"},
	}

	addrParsers := [...]struct {
		name   string
		parser *AddressParser
	}{
		0: {
			name:   "default",
			parser: &AddressParser{},
		},
		1: {
			name:   "permissive",
			parser: &AddressParser{PermissiveLocalPart: true},
		},
	}

	for _, parser := range addrParsers {
		t.Run(parser.name, func(t *testing.T) {
			t.Parallel()
			for i, tc := range mustErrTestCases {
				_, err := parser.parser.Parse(tc.text)
				if err == nil || !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf(`(%s).Parse(%q) #%d want %q, got %v`, parser.name, tc.text, i, tc.wantErrText, err)
				}
			}
		})
	}
}

func TestAddressParser(t *testing.T) {
	tests := []struct {
		addrsStr string
		exp      []*Address
	}{
		// Bare address
		{
			`jdoe@machine.example`,
			[]*Address{{
				LocalPart: []Token{{Type: Atom, Data: []byte("jdoe")}},
				Domain:    []Token{{Type: Atom, Data: []byte("machine.example")}},
			}},
		},
		// RFC 5322, Appendix A.1.1
		{
			`John Doe <jdoe@machine.example>`,
			[]*Address{{
				Leadings: []Token{
					{Type: Atom, Data: []byte("John")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Atom, Data: []byte("Doe")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{{Type: Atom, Data: []byte("jdoe")}},
				Domain:    []Token{{Type: Atom, Data: []byte("machine.example")}},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			}},
		},
		// RFC 5322, Appendix A.1.2
		{
			`"Joe Q. Public" <john.q.public@example.com>`,
			[]*Address{{
				Leadings: []Token{
					{Type: QuotedString, Data: []byte("\"Joe Q. Public\"")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{{Type: Atom, Data: []byte("john.q.public")}},
				Domain:    []Token{{Type: Atom, Data: []byte("example.com")}},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			}},
		},
		{
			`Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>`,
			[]*Address{
				{
					Leadings: []Token{
						{Type: Atom, Data: []byte("Mary")},
						{Type: FWS, Data: []byte(" ")},
						{Type: Atom, Data: []byte("Smith")},
						{Type: FWS, Data: []byte(" ")},
						{Type: Opaque, Data: []byte("<")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("mary")}},
					Domain:    []Token{{Type: Atom, Data: []byte("x.test")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
						{Type: Opaque, Data: []byte(",")},
					},
				},
				{
					Leadings: []Token{
						{Type: FWS, Data: []byte(" ")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("jdoe")}},
					Domain:    []Token{{Type: Atom, Data: []byte("example.org")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(",")},
					},
				},
				{
					Leadings: []Token{
						{Type: FWS, Data: []byte(" ")},
						{Type: Atom, Data: []byte("Who?")},
						{Type: FWS, Data: []byte(" ")},
						{Type: Opaque, Data: []byte("<")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("one")}},
					Domain:    []Token{{Type: Atom, Data: []byte("y.test")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
					},
				},
			},
		},
		{
			`<boss@nil.test>, "Giant; \"Big\" Box" <sysservices@example.net>`,
			[]*Address{
				{
					Leadings:  []Token{{Type: Opaque, Data: []byte("<")}},
					LocalPart: []Token{{Type: Atom, Data: []byte("boss")}},
					Domain:    []Token{{Type: Atom, Data: []byte("nil.test")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
						{Type: Opaque, Data: []byte(",")},
					},
				},
				{
					Leadings: []Token{
						{Type: FWS, Data: []byte(" ")},
						{Type: QuotedString, Data: []byte(`"Giant; \"Big\" Box"`)},
						{Type: FWS, Data: []byte(" ")},
						{Type: Opaque, Data: []byte("<")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("sysservices")}},
					Domain:    []Token{{Type: Atom, Data: []byte("example.net")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
					},
				},
			},
		},
		// RFC 2047 "Q"-encoded ISO-8859-1 address.
		{
			`=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Leadings: []Token{
						{Type: Atom, Data: []byte(`=?iso-8859-1?q?J=F6rg_Doe?=`)},
						{Type: FWS, Data: []byte(" ")},
						{Type: Opaque, Data: []byte("<")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("joerg")}},
					Domain:    []Token{{Type: Atom, Data: []byte("example.com")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
					},
				},
			},
		},
		// Custom example with "." in name. For issue 4938
		{
			`Asem H. <noreply@example.com>`,
			[]*Address{
				{
					Leadings: []Token{
						{Type: Atom, Data: []byte(`Asem`)},
						{Type: FWS, Data: []byte(" ")},
						{Type: Atom, Data: []byte(`H`)},
						{Type: Opaque, Data: []byte(`.`)},
						{Type: FWS, Data: []byte(" ")},
						{Type: Opaque, Data: []byte("<")},
					},
					LocalPart: []Token{{Type: Atom, Data: []byte("noreply")}},
					Domain:    []Token{{Type: Atom, Data: []byte("example.com")}},
					Trailings: []Token{
						{Type: Opaque, Data: []byte(">")},
					},
				},
			},
		},
		// Domain-literal
		{
			`jdoe@[192.168.0.1]`,
			[]*Address{{
				LocalPart: []Token{{Type: Atom, Data: []byte("jdoe")}},
				Domain:    []Token{{Type: DomainLiteral, Data: []byte("[192.168.0.1]")}},
			}},
		},
		{
			`John Doe <jdoe@[192.168.0.1]>`,
			[]*Address{{
				Leadings: []Token{
					{Type: Atom, Data: []byte("John")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Atom, Data: []byte("Doe")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{{Type: Atom, Data: []byte("jdoe")}},
				Domain:    []Token{{Type: DomainLiteral, Data: []byte("[192.168.0.1]")}},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			}},
		},
	}

	ap := AddressParser{}

	for _, test := range tests {
		if len(test.exp) == 1 {
			addr, err := ap.Parse(test.addrsStr)
			if err != nil {
				t.Errorf("Failed parsing (single) %q: %v", test.addrsStr, err)
				continue
			}
			if !reflect.DeepEqual([]*Address{addr}, test.exp) {
				t.Errorf("Parse (single) of %q: got %+v, want %+v", test.addrsStr, addr, test.exp)
			}
		}

		addrs, err := ap.ParseList(test.addrsStr)
		if err != nil {
			t.Errorf("Failed parsing (list) %q: %v", test.addrsStr, err)
			continue
		}
		if !reflect.DeepEqual(addrs, test.exp) {
			t.Errorf("Parse (list) of %q: got %+v, want %+v", test.addrsStr, addrs, test.exp)
		}
	}
}

func TestAddressString(t *testing.T) {
	tests := []struct {
		addr *Address
		exp  string
	}{
		{
			&Address{
				Leadings: []Token{
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte("example.com")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			"<bob@example.com>",
		},
		{ // quoted local parts: RFC 5322, 3.4.1. and 3.2.4.
			&Address{
				Leadings: []Token{
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: QuotedString, Data: []byte(`"my@idiot@address"`)},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte(`example.com`)},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`<"my@idiot@address"@example.com>`,
		},
		{ // quoted local parts
			&Address{
				Leadings: []Token{
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: QuotedString, Data: []byte(`" "`)},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte(`example.com`)},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`<" "@example.com>`,
		},
		{
			&Address{
				Leadings: []Token{
					{Type: QuotedString, Data: []byte(`"Bob"`)},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte("example.com")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`"Bob" <bob@example.com>`,
		},
		{
			&Address{
				Leadings: []Token{
					{Type: Atom, Data: []byte(`=?utf-8?q?B=C3=B6b?=`)},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte("example.com")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`=?utf-8?q?B=C3=B6b?= <bob@example.com>`,
		},
		{
			&Address{
				Leadings: []Token{
					{Type: QuotedString, Data: []byte(`"Bob Jane"`)},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte("example.com")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`"Bob Jane" <bob@example.com>`,
		},
		{
			&Address{
				Leadings: []Token{
					{Type: Atom, Data: []byte("=?utf-8?q?B=C3=B6b_Jac=C3=B6b?=")},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: Atom, Data: []byte("example.com")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`=?utf-8?q?B=C3=B6b_Jac=C3=B6b?= <bob@example.com>`,
		},
		// Domain-literal
		{
			&Address{
				Leadings: []Token{
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: DomainLiteral, Data: []byte("[192.168.0.1]")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			"<bob@[192.168.0.1]>",
		},
		{
			&Address{
				Leadings: []Token{
					{Type: QuotedString, Data: []byte(`"Bob"`)},
					{Type: FWS, Data: []byte(" ")},
					{Type: Opaque, Data: []byte("<")},
				},
				LocalPart: []Token{
					{Type: Atom, Data: []byte("bob")},
				},
				Domain: []Token{
					{Type: DomainLiteral, Data: []byte("[192.168.0.1]")},
				},
				Trailings: []Token{
					{Type: Opaque, Data: []byte(">")},
				},
			},
			`"Bob" <bob@[192.168.0.1]>`,
		},
	}
	for j := 0; j < 2; j++ {
		func(permissiveLocalPart bool) {
			parser := &AddressParser{PermissiveLocalPart: permissiveLocalPart}
			t.Run(fmt.Sprintf("&AddressParser{PermissiveLocalPart:%v}", permissiveLocalPart), func(t *testing.T) {
				t.Parallel()
				for _, test := range tests {
					s := test.addr.RenderAsString(permissiveLocalPart)
					if s != test.exp {
						t.Errorf("Address%+v.RenderAsString(%v) = %v, want %v", *test.addr, permissiveLocalPart, s, test.exp)
						continue
					}

					// Check round-trip.
					a, err := parser.Parse(test.exp)
					if err != nil {
						t.Errorf("(&AddressParser{PermissiveLocalPart:%v}).Parse(%#q): %v", permissiveLocalPart, test.exp, err)
						continue
					}
					if !reflect.DeepEqual(a.GetDisplayName(), test.addr.GetDisplayName()) || !reflect.DeepEqual(a.GetAddress(), test.addr.GetAddress()) {
						t.Errorf("(&AddressParser{PermissiveLocalPart:%v}).Parse(%#q) = %#v, want %#v", permissiveLocalPart, test.exp, a, test.addr)
					}
				}
			})
		}(j == 1)
	}
}

// Check if all valid addresses can be parsed, formatted and parsed again
func TestAddressParsingAndFormatting(t *testing.T) {
	for j := 0; j < 2; j++ {
		func(permissiveLocalPart bool) {
			t.Run(fmt.Sprintf("shouldPass(PermissiveLocalPart=%v)", permissiveLocalPart), func(t *testing.T) {
				t.Parallel()
				// Should pass
				tests := []string{
					`<Bob@example.com>`,
					`<bob.bob@example.com>`,
					`<" "@example.com>`,
					`<some.mail-with-dash@example.com>`,
					`<"dot.and space"@example.com>`,
					`<"very.unusual.@.unusual.com"@example.com>`,
					`<admin@mailserver1>`,
					`<postmaster@localhost>`,
					"<#!$%&'*+-/=?^_`{}|~@example.org>",
					`<"very.(),:;<>[]\".VERY.\"very@\\ \"very\".unusual"@strange.example.com>`, // escaped quotes
					`<"()<>[]:,;@\\\"!#$%&'*+-/=?^_{}| ~.a"@example.org>`,                      // escaped backslashes
					`<"Abc\\@def"@example.com>`,
					`<"Joe\\Blow"@example.com>`,
					`<test1/test2=test3@example.com>`,
					`<def!xyz%abc@example.com>`,
					`<_somename@example.com>`,
					`<joe@uk>`,
					`<~@example.com>`,
					`<"0:"@0>`,
					`<Bob@[192.168.0.1]>`,
				}

				parser := &AddressParser{PermissiveLocalPart: permissiveLocalPart}
				for _, test := range tests {
					addr, err := parser.Parse(test)
					if err != nil {
						t.Errorf("Couldn't parse address %s: %s", test, err.Error())
						continue
					}
					str := addr.RenderAsString(permissiveLocalPart)
					addr, err = parser.Parse(str)
					if err != nil {
						t.Errorf("p.Parse(%q) error: %v", test, err)
						continue
					}

					rendered := addr.RenderAsString(permissiveLocalPart)
					if rendered != test {
						t.Errorf("String() round-trip = %q; want %q", rendered, test)
						continue
					}
				}
			})

			t.Run(fmt.Sprintf("shouldFail(PermissiveLocalPart=%v)", permissiveLocalPart), func(t *testing.T) {
				t.Parallel()
				// Should fail
				badTests := []string{
					`<Abc.example.com>`,
					`<A@b@c@example.com>`,
					`<a"b(c)d,e:f;g<h>i[j\k]l@example.com>`,
					`<just"not"right@example.com>`,
					`<this is"not\allowed@example.com>`,
					`<this\ still\"not\\allowed@example.com>`,
					`<john.doe@example..com>`,
					`<john.doe@example..com>`,
					`<john.doe.@.example.com>`,
					`<@example.com>`,
					`<test@.>`,
					`< @example.com>`,
					`<""test""blah""@example.com>`,
					`<""@0>`,
				}

				parser := &AddressParser{PermissiveLocalPart: permissiveLocalPart}
				for _, test := range badTests {
					_, err := parser.Parse(test)
					if err == nil {
						t.Errorf("Should have failed to parse address: %s", test)
						continue
					}
				}
			})

			t.Run(fmt.Sprintf("shouldEitherPassOrFail(PermissiveLocalPart=%v)", permissiveLocalPart), func(t *testing.T) {
				t.Parallel()
				parser := &AddressParser{PermissiveLocalPart: permissiveLocalPart}
				tests := []string{
					`<john.doe.@example.com>`,
					`<john..doe@example.com>`,
					`<.john.doe@example.com>`,
					`<.@example.com>`,
				}
				for _, test := range tests {
					out, err := parser.Parse(test)
					if permissiveLocalPart {
						if err != nil {
							t.Errorf("Should have passed to parse address: %s (%s)", test, err)
						}
					} else {
						if err == nil {
							t.Errorf("Should have failed to parse address: %s (%s)", test, out.RenderAsString(permissiveLocalPart))
						}
					}
				}
			})
		}(j == 1)
	}

	t.Run("roundtrips", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			input string
			want  string
		}{
			{
				input: `<"..."@test.com>`,
				want:  `<...@test.com>`,
			},
			{
				input: `<"john..doe"@example.com>`,
				want:  `<john..doe@example.com>`,
			},
			{
				input: `<"john.doe."@example.com>`,
				want:  `<john.doe.@example.com>`,
			},
			{
				input: `<".john.doe"@example.com>`,
				want:  `<.john.doe@example.com>`,
			},
			{
				input: `<"."@example.com>`,
				want:  `<.@example.com>`,
			},
			{
				input: `<".."@example.com>`,
				want:  `<..@example.com>`,
			},
			{
				input: `<".bob"@example.com>`,
				want:  `<.bob@example.com>`,
			},
		}

		parser := &AddressParser{PermissiveLocalPart: false}
		for _, test := range tests {
			addr, err := parser.Parse(test.input)
			if err != nil {
				t.Errorf("Couldn't parse address %s: %s", test, err.Error())
				continue
			}
			rendered := addr.RenderAsString(true)
			if rendered != test.want {
				t.Errorf("String() round-trip = %q; want %q", rendered, test)
				continue
			}
		}
	})
}

func TestEmptyAddress(t *testing.T) {
	for j := 0; j < 2; j++ {
		func(permissiveLocalPart bool) {
			parser := &AddressParser{PermissiveLocalPart: permissiveLocalPart}
			t.Run(fmt.Sprintf("permissiveLocalPart=%v", permissiveLocalPart), func(t *testing.T) {
				parsed, err := parser.Parse("")
				if parsed != nil || err == nil {
					t.Errorf(`ParseAddress("") = %v, %v, want nil, error`, parsed, err)
				}
				list, err := parser.ParseList("")
				if len(list) > 0 || err == nil {
					t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
				}
				list, err = parser.ParseList(",")
				if len(list) > 0 || err == nil {
					t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
				}
				list, err = parser.ParseList("a@b c@d")
				if len(list) > 0 || err == nil {
					t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
				}
			})
		}(j == 1)
	}
}
