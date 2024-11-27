package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAddress(t *testing.T) {
	b := []byte("foo@example.com")
	a := &Address{
		LocalPart: []Token{{Type: Atom, Data: b[:3]}},
		Domain:    []Token{{Type: Atom, Data: b[4:]}},
	}
	exp := append([]byte(nil), b...)
	result := a.GetAddress()
	assert.Equal(t, exp, result)
	assert.True(t, &b[0] == &result[0])
	b[3] = ' '
	result = a.GetAddress()
	assert.Equal(t, exp, result)
	assert.False(t, &b[0] == &result[0])
}
