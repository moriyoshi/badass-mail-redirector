//go:build !windows

package uplooker

func GetDefaultHostsFilePath() string {
	return "/etc/hosts"
}
