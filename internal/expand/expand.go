package expand

import (
	"regexp"
)

var re = regexp.MustCompile(`\$\{([a-zA-Z0-9_.-]+)\}`)

func Expand(v string, mapping func(string) string) string {
	return re.ReplaceAllStringFunc(v, func(s string) string {
		return mapping(s[2 : len(s)-1])
	})
}
