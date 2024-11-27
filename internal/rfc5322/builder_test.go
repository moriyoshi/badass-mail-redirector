package rfc5322

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
	"github.com/stretchr/testify/assert"
)

func TestRoundtrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input []byte
	}{
		{
			name: "simple",
			input: []byte(strings.Trim(`
Subject: foo
	bar
	baz
From: abc
	<def@example.com>
To: "ghi"
  <"jkl"@example.com>

body\r\nbody`, "\n")),
		},
		{
			name: "straggler",
			input: []byte(strings.Trim(`
		Straggler
Subject: foo
	bar
	baz
From: abc
	<def@example.com>
To: "ghi"
  <"jkl"@example.com>

body\r\nbody`, "\n")),
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("#%d: %s", i, c.name), func(t *testing.T) {
			t.Parallel()
			buf := &bytes.Buffer{}
			err := Scan(&bufio.BytesReaderWrapper{Reader: bytes.NewReader(c.input)}, &Builder{Writer: buf})
			if assert.NoError(t, err) {
				assert.Equal(t, bytes.ReplaceAll(c.input, []byte{'\n'}, []byte{'\r', '\n'}), buf.Bytes())
			}
		})
	}
}
