package bufio

import (
	_bufio "bufio"
	"io"
)

var ErrBufferFull = _bufio.ErrBufferFull

type Peeker interface {
	Buffered() int
	Peek(n int) ([]byte, error)
	Discard(n int) (int, error)
}

type Scanner interface {
	ReadUpTo(delim byte) ([]byte, bool, error)
}

type BufferedReader interface {
	io.Reader
	io.ByteScanner
	io.WriterTo
	io.RuneScanner
	Peeker
	Scanner
}
