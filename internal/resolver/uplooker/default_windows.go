//go:build windows

package uplooker

import (
	"path/filepath"

	"github.com/moriyoshi/badass-mail-redirector/internal/resolver/internal"
)

func GetDefaultHostsFilePath() string {
	return filepath.Join(internal.GetSystemDirectory(), "Drivers\\etc\\hosts")
}
