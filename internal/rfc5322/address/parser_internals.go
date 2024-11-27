package address

import (
	"errors"
)

type addrParser struct {
	s                   []byte
	i                   int
	permissiveLocalPart bool
	t                   []Token
}

func (p *addrParser) parseAddressList() ([]*Address, error) {
	var list []*Address
	for p.i < len(p.s) {
		addr, comma, err := p.parseAddress(true, true)
		if err != nil {
			return nil, err
		}

		list = append(list, addr)
		if !comma {
			break
		}
	}
	if p.i < len(p.s) {
		return nil, errors.New("invalid address list")
	}
	if len(list) == 0 {
		return nil, errors.New("empty address list")
	}
	return list, nil
}

func (p *addrParser) parseSingleAddress() (*Address, error) {
	addr, comma, err := p.parseAddress(true, false)
	if err != nil {
		return nil, err
	}
	if comma || p.i < len(p.s) {
		return nil, errors.New("expected single address")
	}
	if addr == nil {
		return nil, errors.New("empty address")
	}
	if addr.LocalPart == nil && addr.Domain == nil {
		if len(addr.GroupList) == 0 {
			return nil, errors.New("empty group")
		} else if len(addr.GroupList) > 1 {
			return nil, errors.New("group with multiple addresses")
		}
		return addr.GroupList[0], nil
	}
	return addr, nil
}

func (p *addrParser) consumeSpecials(c byte) bool {
	i := p.i
	for ; i < len(p.s); i++ {
		if p.s[i] != c {
			break
		}
	}
	if i > p.i {
		p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i:i]})
		p.i = i
		return true
	}
	return false
}

// parseAddress parses a single RFC 5322 address at the start of p.
func (p *addrParser) parseAddress(handleGroup bool, commaSeparated bool) (*Address, bool, error) {
	// address = mailbox / group
	// mailbox = name-addr / addr-spec
	// group = display-name ":" [group-list] ";" [CFWS]

	// addr-spec has a more restricted grammar than name-addr,
	// so try parsing it first, and fallback to name-addr.
	// TODO(dsymonds): Is this really correct?

	for {
		if p.i >= len(p.s) {
			return nil, false, nil
		}
		ok, err := p.skipCFWS()
		if ok {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if commaSeparated {
			if !p.consumeSpecials(',') {
				break
			}
		}
		break
	}

	leadings := p.t
	p.t = nil

	addr, err := p.tryConsumingAddrSpec()
	if addr != nil && err == nil {
		comma := false
		for {
			ok, err := p.skipCFWS()
			if err != nil {
				return nil, false, err
			}
			if ok {
				continue
			}
			if commaSeparated {
				if p.consumeSpecials(',') {
					comma = true
				} else {
					break
				}
			}
			break
		}
		addr.Leadings = leadings
		addr.Trailings = p.t
		p.t = nil
		return addr, comma, nil
	}

	p.t = leadings

	// display-name
	_, err = p.tryConsumingPhrase()
	if err != nil {
		return nil, false, err
	}

	p.tryConsumingSpaces()

	if p.i < len(p.s) {
		switch p.s[p.i] {
		case '<':
			p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i : p.i+1]})
			p.i++
			_, err = p.skipCFWS()
			if err != nil {
				return nil, false, err
			}
			leadings = p.t
			p.t = nil
			// angle-addr
			addr, err = p.tryConsumingAddrSpec()
			if err != nil {
				return nil, false, err
			}
			if addr == nil {
				return nil, false, errors.New("no addr-spec")
			}
			_, err := p.skipCFWS()
			if err != nil {
				return nil, false, err
			}
			if p.i >= len(p.s) || p.s[p.i] != '>' {
				return nil, false, errors.New("unclosed angle-addr")
			}
			p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i : p.i+1]})
			p.i++
			var comma bool
			if commaSeparated && p.i < len(p.s) && p.s[p.i] == ',' {
				comma = true
				p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i : p.i+1]})
				p.i++
			}
			addr.Leadings = leadings
			addr.Trailings = p.t
			p.t = nil
			return addr, comma, nil
		case ':':
			if handleGroup {
				p.t = append(p.t, Token{Type: Atom, Data: p.s[p.i : p.i+1]})
				p.i++
				leadings = p.t
				p.t = nil
				addr, err := p.consumeGroupList()
				if err != nil {
					return nil, false, err
				}
				_, err = p.skipCFWS()
				if err != nil {
					return nil, false, err
				}
				addr.Leadings = leadings
				addr.Trailings = p.t
				p.t = nil
				return addr, false, nil
			}
		}
	}
	{
		_, err = p.skipCFWS()
		if err != nil {
			return nil, false, err
		}
		cn := 0
		for i := 0; i < len(p.t); i++ {
			token := p.t[i]
			if token.Type == Atom {
				cn++
				i++
			outer:
				for ; i < len(p.t); i++ {
					token = p.t[i]
					if token.Type == Opaque {
						for _, c := range token.Data {
							if c != '.' {
								break outer
							}
						}
					} else if token.Type != Atom {
						break
					}
				}
			}
		}
		if cn == 1 {
			// The input is like "foo.bar"; it's possible the input
			// meant to be "foo.bar@domain", or "foo.bar <...>".
			return nil, false, errors.New("missing '@' or angle-addr")
		} else {
			// The input is like "Full Name", which couldn't possibly be a
			// valid email address if followed by "@domain"; the input
			// likely meant to be "Full Name <...>".
			return nil, false, errors.New("no angle-addr")
		}
	}
}

func (p *addrParser) consumeGroupList() (addr *Address, err error) {
	var group []*Address
	// handle empty group.
	for {
		// embedded groups not allowed.
		var gaddr *Address
		var comma bool
		gaddr, comma, err = p.parseAddress(false, true)
		if err != nil {
			return
		}
		group = append(group, gaddr)
		if !comma {
			break
		}
	}
	if p.i < len(p.s) && p.s[p.i] == ';' {
		p.t = append(p.t, Token{Type: Atom, Data: p.s[p.i : p.i+1]})
		p.i++
	} else {
		err = errors.New("missing ; in group")
	}
	addr = &Address{
		GroupList: group,
		Trailings: p.t,
	}
	p.t = nil
	return
}

// consumeAddrSpec parses a single RFC 5322 addr-spec at the start of p.
func (p *addrParser) tryConsumingAddrSpec() (*Address, error) {
	// local-part = dot-atom / quoted-string
	if p.i >= len(p.s) {
		return nil, errors.New("no addr-spec")
	}
	orig := *p
	_, err := p.skipCFWS()
	if err != nil {
		return nil, err
	}

	var ok bool
	if ok, err = p.tryConsumingQuotedString(); ok {
		if len(p.t[len(p.t)-1].Data) == 2 {
			err = errors.New("empty quoted string in addr-spec")
		}
	} else {
		if err != nil {
			return nil, err
		}
		// dot-atom
		ok, err = p.consumeAtom(true, p.permissiveLocalPart)
		if !ok {
			return nil, errors.New("invalid string")
		}
	}
	if err != nil {
		// restore the state and then return
		*p = orig
		return nil, err
	}

	_, err = p.skipCFWS()
	if err != nil {
		*p = orig
		return nil, err
	}

	localPart := p.t
	p.t = nil

	if p.i >= len(p.s) || p.s[p.i] != '@' {
		// restore the state and then return
		*p = orig
		return nil, errors.New("missing @ in addr-spec")
	}
	p.i++

	// domain = dot-atom / domain-literal
	_, err = p.skipCFWS()
	if err != nil {
		*p = orig
		return nil, err
	}
	if p.i >= len(p.s) {
		// restore the state and then return
		*p = orig
		return nil, errors.New("no domain in addr-spec")
	}

	ok, err = p.tryConsumingDomainLiteral()
	if err != nil {
		// restore the state and then return
		*p = orig
		return nil, err
	}
	if !ok {
		// dot-atom
		ok, err := p.consumeAtom(true, false)
		if err != nil {
			// restore the state and then return
			*p = orig
			return nil, err
		}
		if !ok {
			*p = orig
			return nil, errors.New("invalid string")
		}
	}

	domain := p.t
	p.t = nil

	return &Address{
		LocalPart: localPart,
		Domain:    domain,
	}, nil
}

// consumeWord parses an RFC 5322 word at the current position.
func (p *addrParser) consumeWord() (consumed bool, err error) {
	ok, err := p.skipCFWS()
	consumed = consumed || ok
	if err != nil {
		return
	}
	if ok, err = p.tryConsumingQuotedString(); ok {
		consumed = true
	} else {
		if err != nil {
			return
		}
		ok, err = p.consumeAtom(false, false)
		if err != nil {
			return
		}
		if !ok {
			return
		}
		consumed = true
	}
	_, err = p.skipCFWS()
	return
}

// tryConsumingPhrase parses the RFC 5322 phrase at the start of p.
func (p *addrParser) tryConsumingPhrase() (bool, error) {
	// phrase = 1*word
	// obs-phrase = word *(word / "." / CFWS)
	ok, err := p.consumeWord()
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	for p.i < len(p.s) {
		// obs-phrase allows CFWS after one word
		ok, err := p.skipCFWS()
		if ok {
			continue
		}
		if err != nil {
			return true, err
		}
		if p.consumeSpecials('.') {
			continue
		}
		ok, err = p.consumeWord()
		if err != nil {
			return true, err
		}
		if !ok {
			break
		}
	}
	return true, nil
}

// tryConsumingQuotedString parses the quoted string at the start of p.
func (p *addrParser) tryConsumingQuotedString() (bool, error) {
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return false, nil
	}

	i := p.i + 1
outer:
	for i < len(p.s) {
		c := p.s[i]
		i++
		switch c {
		case '"':
			break outer
		case '\\':
			if i >= len(p.s) {
				break outer
			}
			c := p.s[i]
			i++
			if !isVchar(c) && !isWSP(c) {
				goto bad
			}
		default:
			if !isQtext(c) && !isWSP(c) {
				goto bad
			}
		}
	}
	if i >= len(p.s) {
		p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i:]})
		p.i = len(p.s)
		return false, nil
	} else {
		p.t = append(p.t, Token{Type: QuotedString, Data: p.s[p.i:i]})
		p.i = i
		return true, nil
	}
bad:
	return false, errors.New("bad character in quoted-string")
}

// consumeAtom parses an RFC 5322 atom at the start of p.
// If dot is true, consumeAtom parses an RFC 5322 dot-atom instead.
// If permissive is true, consumeAtom will not fail on:
// - leading/trailing/double dots in the atom (see golang.org/issue/4938)
func (p *addrParser) consumeAtom(dot bool, permissive bool) (bool, error) {
	i := p.i
	for ; i < len(p.s); i++ {
		if !isAtext(p.s[i], dot) {
			break
		}
	}
	if i == p.i {
		return false, nil
	}

	atom := p.s[p.i:i]
	p.i = i

	if !permissive {
		i := 0
		for i < len(atom) {
			c := atom[i]
			i++
			if c == '.' {
				if i == 1 {
					return true, errors.New("leading dot in atom")
				} else {
					if i == len(atom) {
						return true, errors.New("trailing dot in atom")
					} else if atom[i] == '.' {
						return true, errors.New("double dot in atom")
					}
				}
			}
		}
	}

	p.t = append(p.t, Token{Type: Atom, Data: atom})
	return true, nil
}

// consumeDomainLiteral parses an RFC 5322 domain-literal at the start of p.
func (p *addrParser) tryConsumingDomainLiteral() (bool, error) {
	if p.i >= len(p.s) || p.s[p.i] != '[' {
		return false, nil
	}
	bad := false
	i := p.i + 1
	for {
		if i >= len(p.s) {
			p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i:]})
			p.i = i
			return true, errors.New("unclosed domain-literal")
		}
		c := p.s[i]
		i++
		if c == ']' {
			break
		} else {
			if !isDtext(c) && !isWSP(c) {
				bad = true
			}
		}
	}
	if bad {
		p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i:i]})
		p.i = i
		return true, errors.New("bad character in domain-literal")
	} else {
		p.t = append(p.t, Token{Type: DomainLiteral, Data: p.s[p.i:i]})
		p.i = i
		return true, nil
	}
}

// tryConsumingSpaces skips the leading space and tab characters.
func (p *addrParser) tryConsumingSpaces() bool {
	s := p.i
	i := s
	for ; i < len(p.s); i++ {
		if p.s[i] != ' ' && p.s[i] != '\t' {
			break
		}
	}
	p.i = i
	if i > s {
		p.t = append(p.t, Token{Type: FWS, Data: p.s[s:i]})
		return true
	} else {
		return false
	}
}

func (p *addrParser) tryConsumingFWS() (bool, error) {
	i := p.i
	if i >= len(p.s) {
		return false, nil
	}
	for {
		if p.s[i] != ' ' && p.s[i] != '\t' {
			break
		}
		i++
		if i >= len(p.s) {
			goto eligible
		}
	}
	if p.s[i] == '\r' {
		i++
		if i >= len(p.s) {
			goto opaque
		}
		if p.s[i] == '\n' {
			i++
			if i >= len(p.s) {
				goto opaque
			}
		} else {
			goto opaque
		}
	} else {
		if i > p.i {
			goto eligible
		} else {
			return false, nil
		}
	}
	{
		s := i
		for ; i < len(p.s); i++ {
			if p.s[i] != ' ' && p.s[i] != '\t' {
				break
			}
		}
		if i > s {
			goto eligible
		}
	}
opaque:
	p.t = append(p.t, Token{Type: Opaque, Data: p.s[p.i:i]})
	p.i = i
	return true, errors.New("unexpected sequences")
eligible:
	p.t = append(p.t, Token{Type: FWS, Data: p.s[p.i:i]})
	p.i = i
	return true, nil
}

// skipCFWS skips CFWS as defined in RFC5322.
func (p *addrParser) skipCFWS() (consumed bool, err error) {
	consumed = false
	for p.i < len(p.s) {
		var ok bool
		ok, err = p.tryConsumingFWS()
		consumed = consumed || ok
		if err != nil {
			break
		}
		if ok {
			continue
		}
		ok, err = p.tryConsumingComment()
		consumed = consumed || ok
		if err != nil {
			break
		}
		if !ok {
			break
		}
	}
	return
}

func (p *addrParser) tryConsumingComment() (bool, error) {
	if p.i >= len(p.s) || p.s[p.i] != '(' {
		return false, nil
	}

	s := p.i
	i := s + 1
	depth := 1
	for i < len(p.s) {
		c := p.s[i]
		i++
		if c == '\\' && i < len(p.s) {
			i++
		} else if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				break
			}
		}
	}
	p.i = i
	if depth == 0 {
		p.t = append(p.t, Token{Type: Comment, Data: p.s[s:i]})
		return true, nil
	} else {
		p.t = append(p.t, Token{Type: Opaque, Data: p.s[s:i]})
		return false, errors.New("misformatted parenthetical comment")
	}
}

// isAtext reports whether r is an RFC 5322 atext character.
// If dot is true, period is included.
func isAtext(r byte, dot bool) bool {
	switch r {
	case '.':
		return dot

	// RFC 5322 3.2.3. specials
	case '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '"': // RFC 5322 3.2.3. specials
		return false
	}
	return isVchar(r)
}

func isBackslashOrQuote(r byte) bool {
	return r == '\\' || r == '"'
}

// isQtext reports whether r is an RFC 5322 qtext character.
func isQtext(r byte) bool {
	// Printable US-ASCII, excluding backslash or quote.
	if isBackslashOrQuote(r) {
		return false
	}
	return isVchar(r)
}

// isVchar reports whether r is an RFC 5322 VCHAR character.
func isVchar(r byte) bool {
	// Visible (printing) characters.
	return '!' <= r && r <= '~' || r >= 0x80
}

// isWSP reports whether r is a WSP (white space).
// WSP is a space or horizontal tab (RFC 5234 Appendix B).
func isWSP(r byte) bool {
	return r == ' ' || r == '\t'
}

// isDtext reports whether r is an RFC 5322 dtext character.
func isDtext(r byte) bool {
	// Printable US-ASCII, excluding "[", "]", or "\".
	if r == '[' || r == ']' || r == '\\' {
		return false
	}
	return isVchar(r)
}
