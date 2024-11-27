//go:build !windows

package resolver

func init() {
	loader, err := NewResolvConfLoader()
	if err != nil {
		panic(err)
	}
	defaultConfigLoader = loader.Get
}
