package bufio

import (
	_bufio "bufio"
	"bytes"
	"io"
)

type BytesReaderWrapper struct {
	*bytes.Reader
}

func (w *BytesReaderWrapper) Buffered() int {
	p, _ := w.Seek(0, io.SeekCurrent)
	return w.Len() - int(p)
}

func (w *BytesReaderWrapper) Peek(n int) ([]byte, error) {
	b := make([]byte, n)
	nn, err := w.Read(b)
	if err != nil {
		b = b[:nn]
	}
	for i := 0; i < nn; i++ {
		err := w.UnreadByte()
		if err != nil {
			return b, err
		}
	}
	return b, err
}

var bufForDiscard [8192]byte

func (w *BytesReaderWrapper) Discard(n int) (int, error) {
	nn := 0
	for nn < n {
		m := len(bufForDiscard)
		if nn+m > n {
			m = n - nn
		}
		n, err := w.Read(bufForDiscard[:m])
		nn += n
		if err != nil {
			return nn, err
		}
	}
	return nn, nil
}

func (w *BytesReaderWrapper) ReadUpTo(delim byte) ([]byte, bool, error) {
	var b []byte
	for {
		c, err := w.ReadByte()
		if err != nil {
			return b, true, err
		}
		b = append(b, c)
		if c == delim {
			break
		}
	}
	return b, true, nil
}

var _ BufferedReader = &BytesReaderWrapper{}

type BufferWrapper struct {
	*_bufio.Reader
}

func (w *BufferWrapper) ReadUpTo(delim byte) ([]byte, bool, error) {
	b, err := w.ReadSlice(delim)
	return b, false, err
}

var _ BufferedReader = &BufferWrapper{}
