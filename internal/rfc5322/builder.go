package rfc5322

import (
	"io"

	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
)

type Builder struct {
	io.Writer
	shortWrite bool
}

var newline = []byte{'\r', '\n'}

func (bl *Builder) write(b []byte) error {
	n, err := bl.Writer.Write(b)
	if n != len(b) {
		bl.shortWrite = true
	}
	if err == nil && bl.shortWrite {
		err = io.ErrShortWrite
	}
	return err
}

func (bl *Builder) HandleStraggler(b []byte) error {
	err := bl.write(b)
	if err != nil {
		return err
	}
	return bl.write(newline)
}

func (bl *Builder) HandleHeaderLine(chunks [][]byte) error {
	for _, chunk := range chunks {
		err := bl.write(chunk)
		if err != nil {
			return err
		}
		err = bl.write(newline)
		if err != nil {
			return err
		}
	}
	return nil
}

func (bl *Builder) HandleBody(r bufio.BufferedReader) error {
	err := bl.write(newline)
	if err != nil {
		return err
	}
	_, err = io.Copy(bl.Writer, r)
	return err
}

func (bl *Builder) ShortWrite() bool {
	return bl.shortWrite
}
