package expand

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpand(t *testing.T) {
	assert.Equal(t, "foo", Expand("${foo}", func(s string) string { return s }))
}
