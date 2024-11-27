package address

import (
	"bytes"
)

type AddressRenderer struct {
	Wrap                []byte
	WrapLen             int
	PermissiveLocalPart bool
}

// AppendAddress appends the address to buf in RFC 5322 format.
func (ar *AddressRenderer) appendAddress(b []byte, a *Address) []byte {
	localPart := appendAtomOrQuotedString(nil, a.GetLocalPart(), true, ar.PermissiveLocalPart)
	domain := a.GetDomain()

	n := len(localPart) + 1 + len(domain)

	nReq := len(b) + n + len(ar.Wrap) + 4
	if cap(b) < nReq {
		newBuf := make([]byte, len(b), nReq)
		copy(newBuf, b)
		b = newBuf
	}

	lnl := bytes.LastIndexByte(b, '\n') + 1
	if len(b)+n-lnl >= ar.WrapLen {
		b = append(b, ar.Wrap...)
	}
	b = append(b, '<')
	b = append(b, localPart...)
	b = append(b, '@')
	b = append(b, domain...)
	b = append(b, '>')
	return b
}

func (ar *AddressRenderer) appendAddressList(b []byte, addrs []*Address) []byte {
	for i, addr := range addrs {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b = ar.appendAddress(b, addr)
	}
	return b
}

func (ar *AddressRenderer) AppendName(b []byte, a *Address) []byte {
	var s int
	var token Token
	for s, token = range a.Leadings {
		if token.Type != FWS {
			break
		}
	}
	if s >= len(a.Leadings) {
		return b
	}
	nr := len(b)
	for _, token := range a.Leadings[s:] {
		nr += len(token.Data) + len(ar.Wrap)
	}
	if cap(b) < nr {
		newBuf := make([]byte, len(b), nr)
		copy(newBuf, b)
		b = newBuf
	}
	lnl := bytes.LastIndexByte(b, '\n') + 1
	nlo := bytes.LastIndexByte(ar.Wrap, '\n') + 1

outer:
	for i, token := range a.Leadings[s:] {
		switch token.Type {
		case FWS:
			if len(b)+len(token.Data)-lnl >= ar.WrapLen {
				b = append(b, ar.Wrap...)
				lnl = len(b) - nlo
			} else {
				if i > 0 {
					b = append(b, ' ')
				}
			}
		case Opaque:
			if len(token.Data) == 1 && token.Data[0] == '<' {
				break outer
			}
			b = append(b, token.Data...)
		default:
			b = append(b, token.Data...)
		}
	}
	return b
}

func (ar *AddressRenderer) AppendAddressOrGroupList(b []byte, a *Address) []byte {
	if len(a.GroupList) > 0 {
		return ar.appendAddressList(b, a.GroupList)
	}
	return ar.appendAddress(b, a)
}

func (ar *AddressRenderer) Append(b []byte, a *Address) []byte {
	return ar.AppendAddressOrGroupList(ar.AppendName(b, a), a)
}

func (ar *AddressRenderer) AppendList(b []byte, addrs []*Address) []byte {
	for i, addr := range addrs {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b = ar.Append(b, addr)
	}
	return b
}

// quoteString renders a string as an RFC 5322 quoted-string.
func appendQuotedString(b []byte, v []byte) []byte {
	nr := len(b) + len(v) + ((len(v) + 1) >> 1) + 4
	if cap(b) < nr {
		nb := make([]byte, len(b), nr)
		copy(nb, b)
		b = nb
	}
	b = append(b, '"')
	s := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		u := isBackslashOrQuote(c)
		var l int
		if u {
			l = 2
		} else {
			l = 1
		}
		if cap(b) < len(b)+l {
			nb := make([]byte, len(b), (len(v)<<1)+4)
			copy(nb, b)
			b = nb
		}
		if u {
			b = append(b, v[s:i]...)
			b = append(b, '\\')
			b = append(b, c)
			s = i + 1
		}
	}
	b = append(b, v[s:]...)
	b = append(b, '"')
	return b
}

func tryAppendingAtom(b []byte, v []byte, dot bool, permissive bool) ([]byte, bool) {
	if len(v) == 0 {
		return b, false
	}
	if dot {
		for i := 0; i < len(v); i++ {
			if v[i] == '.' {
				if !permissive {
					if i == 0 {
						return b, false
					} else if i == len(v)-1 {
						return b, false
					} else if v[i+1] == '.' {
						return b, false
					}
				}
			} else if !isAtext(v[i], true) {
				return b, false
			}
		}
	} else {
		for i := 0; i < len(v); i++ {
			if !isAtext(v[i], false) {
				return b, false
			}
		}
	}
	return append(b, v...), true
}

func appendAtomOrQuotedString(b []byte, v []byte, dot bool, permissive bool) []byte {
	var ok bool
	if b, ok = tryAppendingAtom(b, v, dot, permissive); !ok {
		b = appendQuotedString(b, v)
	}
	return b
}
