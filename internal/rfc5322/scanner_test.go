package rfc5322

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
	"github.com/stretchr/testify/assert"
)

type result struct {
	headers    [][]string
	body       string
	stragglers []string
}

type testHandler struct {
	result
}

func (h *testHandler) HandleStraggler(b []byte) error {
	h.result.stragglers = append(h.result.stragglers, string(b))
	return nil
}

func (h *testHandler) HandleHeaderLine(hl [][]byte) error {
	chunks := make([]string, len(hl))
	for i, chunk := range hl {
		chunks[i] = string(chunk)
	}
	h.result.headers = append(h.result.headers, chunks)
	return nil
}

func (h *testHandler) HandleBody(b bufio.BufferedReader) error {
	bb, err := io.ReadAll(b)
	if err != nil {
		return err
	}
	h.result.body = string(bb)
	return nil
}

func TestScan(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		expected result
		input    []byte
	}{
		{
			name: "simple",
			expected: result{
				headers: [][]string{
					{"Subject: foo", "\tbar", "\tbaz"},
					{"From: abc", "\t<def@example.com>"},
					{"To: \"ghi\"", "  <\"jkl\"@example.com>"},
				},
				body:       "body\nbody",
				stragglers: nil,
			},
			input: []byte(strings.Trim(`
Subject: foo
	bar
	baz
From: abc
	<def@example.com>
To: "ghi"
  <"jkl"@example.com>

body
body`, "\n")),
		},
		{
			name: "straggler",
			expected: result{
				headers: [][]string{
					{"Subject: foo", "\tbar", "\tbaz"},
					{"From: abc", "\t<def@example.com>"},
					{"To: \"ghi\"", "  <\"jkl\"@example.com>"},
				},
				body:       "body\nbody",
				stragglers: []string{"\t\tStraggler"},
			},
			input: []byte(strings.Trim(`
		Straggler
Subject: foo
	bar
	baz
From: abc
	<def@example.com>
To: "ghi"
  <"jkl"@example.com>

body
body`, "\n")),
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("#%d: %s", i, c.name), func(t *testing.T) {
			t.Parallel()
			h := &testHandler{}
			err := Scan(&bufio.BytesReaderWrapper{Reader: bytes.NewReader(c.input)}, h)
			if assert.NoError(t, err) {
				assert.Equal(t, c.expected, h.result)
			}
		})
	}
}
