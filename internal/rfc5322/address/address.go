// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package address

import (
	"bytes"
	"unsafe"
)

type TokenType int

const (
	Atom TokenType = iota
	QuotedString
	DomainLiteral
	FWS
	Comment
	Opaque
)

type Token struct {
	Type TokenType
	Data []byte
}

// unescapeQuotedString unescapes a quoted string.
func unescapeQuotedString(b []byte) []byte {
	var r []byte
	s := 0
	i := 0
	for ; i < len(b); i++ {
		if b[i] == '\\' {
			if r == nil {
				r = make([]byte, 0, len(b))
			}
			r = append(r, b[s:i]...)
			i++
			if i >= len(b) {
				r = append(r, '\\')
				break
			}
			r = append(r, b[i])
			s = i + 1
		}
	}
	if r != nil {
		r = append(r, b[s:]...)
		return r
	} else {
		return b
	}
}

func (t Token) ValueBytes() []byte {
	switch t.Type {
	case QuotedString:
		return unescapeQuotedString(t.Data[1 : len(t.Data)-1])
	default:
		return t.Data
	}
}

// Address represents a single mail address.
// An address such as "Barry Gibbs <bg@example.com>" is represented
// as Address{Name: "Barry Gibbs", Address: "bg@example.com"}.
type Address struct {
	Leadings  []Token // Display name or something
	LocalPart []Token // user
	Domain    []Token // domain
	GroupList []*Address
	Trailings []Token
}

func (a *Address) GetDisplayName() []byte {
	i := 0
	for ; i < len(a.Leadings); i++ {
		token := &a.Leadings[i]
		if token.Type == Atom || token.Type == QuotedString {
			break
		}
	}
	var chunks [][]byte
	var lastChunk *[]byte
	for ; i < len(a.Leadings); i++ {
		token := &a.Leadings[i]
		if token.Type == Atom || token.Type == FWS || token.Type == QuotedString {
			chunk := token.ValueBytes()
			if lastChunk != nil {
				// merge adjacent chunks
				if uintptr(unsafe.Pointer(&(*lastChunk)[len(*lastChunk)-1]))+1 == uintptr(unsafe.Pointer(&chunk[0])) {
					*lastChunk = (*lastChunk)[:len(*lastChunk)+len(chunk)]
					continue
				}
			}
			chunks = append(chunks, chunk)
			lastChunk = &chunks[len(chunks)-1]
		}
	}
	if len(chunks) == 1 {
		return chunks[0]
	} else {
		return bytes.Join(chunks, nil)
	}
}

func firstMeaningfulToken(tokens []Token) (found bool, token Token) {
	for _, token = range tokens {
		switch token.Type {
		case Atom, QuotedString, DomainLiteral:
			found = true
			return
		}
	}
	return
}

func (a *Address) GetLocalPart() []byte {
	if ok, token := firstMeaningfulToken(a.LocalPart); ok {
		return token.ValueBytes()
	}
	return nil
}

func (a *Address) GetDomain() []byte {
	if ok, token := firstMeaningfulToken(a.Domain); ok {
		return token.ValueBytes()
	}
	return nil
}

func (a *Address) GetAddress() []byte {
	var localPart []byte
	var domain []byte

	if ok, token := firstMeaningfulToken(a.LocalPart); ok {
		localPart = token.Data
	}
	if ok, token := firstMeaningfulToken(a.Domain); ok {
		domain = token.Data
	}

	chunks := make([][]byte, 0, 3)
	if cap(localPart) > len(localPart) && localPart[:len(localPart)+1][len(localPart)] == '@' {
		chunks = append(chunks, localPart[:len(localPart)+1])
	} else {
		chunks = append(chunks, localPart)
		chunks = append(chunks, atmarkToken.Data)
	}
	if len(chunks) == 1 && uintptr(unsafe.Pointer(&(chunks[0])[len(chunks[0])-1]))+1 == uintptr(unsafe.Pointer(&domain[0])) {
		chunks[0] = chunks[0][:len(chunks[0])+len(domain)]
	} else {
		chunks = append(chunks, domain)
	}
	if len(chunks) == 1 {
		return chunks[0]
	} else {
		return bytes.Join(chunks, nil)
	}
}

var atmarkToken = Token{
	Type: Opaque,
	Data: []byte{'@'},
}

func (a *Address) Tokens() []Token {
	var tokens []Token
	if len(a.GroupList) != 0 {
		tokens = make([]Token, 0, len(a.Leadings)+len(a.Trailings)+2)
		tokens = append(tokens, a.Leadings...)
		for _, addr := range a.GroupList {
			tokens = append(tokens, addr.Tokens()...)
		}
		tokens = append(tokens, a.Trailings...)
	} else {
		tokens = make([]Token, len(a.Leadings)+len(a.LocalPart)+len(a.Domain)+len(a.Trailings)+1)
		copy(tokens, a.Leadings)
		copy(tokens[len(a.Leadings):], a.LocalPart)
		tokens[len(a.Leadings)+len(a.LocalPart)] = atmarkToken
		copy(tokens[len(a.Leadings)+len(a.LocalPart)+1:], a.Domain)
		copy(tokens[len(a.Leadings)+len(a.LocalPart)+1+len(a.Domain):], a.Trailings)
	}
	return tokens
}

func (a *Address) Bytes() []byte {
	tokens := a.Tokens()
	chunks := make([][]byte, 0, len(tokens))

	var lastChunk *[]byte
	for i := 0; i < len(tokens); i++ {
		token := &tokens[i]
		chunk := token.Data
		if lastChunk != nil {
			// merge adjacent chunks
			if uintptr(unsafe.Pointer(&(*lastChunk)[len(*lastChunk)-1]))+1 == uintptr(unsafe.Pointer(&chunk[0])) {
				*lastChunk = (*lastChunk)[:len(*lastChunk)+len(chunk)]
				continue
			}
		}
		chunks = append(chunks, chunk)
		lastChunk = &chunks[len(chunks)-1]
	}
	if len(chunks) == 1 {
		return chunks[0]
	} else {
		return bytes.Join(chunks, nil)
	}
}

func (a *Address) String() string {
	return string(a.Bytes())
}
