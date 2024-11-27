package rfc5322

import (
	"io"

	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
)

type ScannerHandler interface {
	HandleStraggler([]byte) error
	HandleHeaderLine([][]byte) error
	HandleBody(bufio.BufferedReader) error
}

func readLineSlice(r bufio.BufferedReader) ([]byte, bool, error) {
	l, borrowable, err := r.ReadUpTo('\n')
	if err == bufio.ErrBufferFull {
		err = nil
		if l[len(l)-1] == '\r' {
			l = l[:len(l)-1]
			err = r.UnreadByte()
		}
	}
	if len(l) == 0 {
		return nil, true, err
	}
	if l[len(l)-1] == '\n' {
		if len(l) >= 2 && l[len(l)-2] == '\r' {
			l = l[:len(l)-2]
		} else {
			l = l[:len(l)-1]
		}
	}
	return l, borrowable, err
}

func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t'
}

func Scan(r bufio.BufferedReader, handler ScannerHandler) error {
	var chunks [][]byte
	var eof bool
	for !eof {
		l, borrowable, err := readLineSlice(r)
		if err != nil {
			if err == io.EOF {
				eof = true
			} else {
				return err
			}
		}
		if len(l) > 0 && isWhitespace(l[0]) {
			if len(chunks) == 0 {
				err = handler.HandleStraggler(l)
				if err != nil {
					return err
				}
				continue
			}
		} else {
			if len(chunks) > 0 {
				err = handler.HandleHeaderLine(chunks)
				if err != nil {
					return err
				}
				chunks = chunks[:0]
			}
			if len(l) == 0 {
				break
			}
		}
		var b []byte
		if !borrowable {
			b = make([]byte, len(l))
			copy(b, l)
		} else {
			b = l
		}
		chunks = append(chunks, b)
	}

	return handler.HandleBody(r)
}

type functionBackedScannerHandler struct {
	StragglerHandler  func([]byte) error
	HeaderLineHandler func([][]byte) error
	BodyHandler       func(bufio.BufferedReader) error
}

func (h *functionBackedScannerHandler) HandleStraggler(l []byte) error {
	if h.StragglerHandler == nil {
		return nil
	}
	return h.StragglerHandler(l)
}

func (h *functionBackedScannerHandler) HandleHeaderLine(l [][]byte) error {
	if h.HeaderLineHandler == nil {
		return nil
	}
	return h.HeaderLineHandler(l)
}

func (h *functionBackedScannerHandler) HandleBody(r bufio.BufferedReader) error {
	if h.BodyHandler == nil {
		return nil
	}
	return h.BodyHandler(r)
}

func ScannerHandlerFromFunctions(
	stragglerHandler func([]byte) error,
	headerLineHandler func([][]byte) error,
	bodyHandler func(bufio.BufferedReader) error,
) ScannerHandler {
	return &functionBackedScannerHandler{
		StragglerHandler:  stragglerHandler,
		HeaderLineHandler: headerLineHandler,
		BodyHandler:       bodyHandler,
	}
}
