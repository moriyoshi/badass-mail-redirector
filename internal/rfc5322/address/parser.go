// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package mail implements parsing of mail messages.

For the most part, this package follows the syntax as specified by RFC 5322 and
extended by RFC 6532.
Notable divergences:
  - Obsolete address formats are not parsed, including addresses with
    embedded route information.
  - The full range of spacing (the CFWS syntax element) is not supported,
    such as breaking addresses across lines.
  - No unicode normalization is performed.
  - A leading From line is permitted, as in mbox format (RFC 4155).
*/
package address

import (
	"math"
)

// An AddressParser is an RFC 5322 address parser.
type AddressParser struct {
	// WordDecoder optionally specifies a decoder for RFC 2047 encoded-words.
	PermissiveLocalPart bool
}

// Parse parses a single RFC 5322 address of the
// form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) Parse(address string) (*Address, error) {
	return (&addrParser{s: []byte(address), permissiveLocalPart: p.PermissiveLocalPart}).parseSingleAddress()
}

// Parse parses a single RFC 5322 address of the
// form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) ParseBytes(address []byte) (*Address, error) {
	return (&addrParser{s: address, permissiveLocalPart: p.PermissiveLocalPart}).parseSingleAddress()
}

// ParseList parses the given string as a list of comma-separated addresses
// of the form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) ParseList(list string) ([]*Address, error) {
	return (&addrParser{s: []byte(list), permissiveLocalPart: p.PermissiveLocalPart}).parseAddressList()
}

// ParseList parses the given string as a list of comma-separated addresses
// of the form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) ParseListBytes(list []byte) ([]*Address, error) {
	return (&addrParser{s: list, permissiveLocalPart: p.PermissiveLocalPart}).parseAddressList()
}

// String formats the address as a valid RFC 5322 address.
// If the address's name contains non-ASCII characters
// the name will be rendered according to RFC 2047.
func (a *Address) RenderAsString(permissiveLocalPart bool) string {
	return string((&AddressRenderer{
		Wrap:                nil,
		WrapLen:             math.MaxInt64,
		PermissiveLocalPart: permissiveLocalPart,
	}).Append(nil, a))
}
