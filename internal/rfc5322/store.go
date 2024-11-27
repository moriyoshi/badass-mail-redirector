package rfc5322

import (
	"bytes"
	"io"

	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
)

type ComponentType int

const (
	Header ComponentType = iota
	Straggler
	Body
)

type Component struct {
	Type ComponentType
	Data [][]byte
}

type Store []Component

func (s *Store) HandleStraggler(b []byte) error {
	b = append([]byte(nil), b...)
	*s = append(*s, Component{Type: Straggler, Data: [][]byte{b}})
	return nil
}

func (s *Store) HandleHeaderLine(chunks [][]byte) error {
	*s = append(*s, Component{Type: Header, Data: chunks})
	return nil
}

func (s *Store) HandleBody(r bufio.BufferedReader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	*s = append(*s, Component{Type: Body, Data: [][]byte{body}})
	return nil
}

func (s *Store) Replay(h ScannerHandler) error {
	for _, c := range *s {
		switch c.Type {
		case Header:
			if err := h.HandleHeaderLine(c.Data); err != nil {
				return err
			}
		case Straggler:
			if err := h.HandleStraggler(c.Data[0]); err != nil {
				return err
			}
		case Body:
			if err := h.HandleBody(&bufio.BytesReaderWrapper{Reader: bytes.NewReader(c.Data[0])}); err != nil {
				return err
			}
		}
	}
	return nil
}
