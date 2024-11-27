package resolver

import "time"

type OptionFuncHook[T any] struct {
	fn   func(loader any, value T) (bool, error)
	next *OptionFuncHook[T]
}

func (hook *OptionFuncHook[T]) Apply(loader any, value T) error {
	for hook != nil {
		ok, err := hook.fn(loader, value)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		hook = hook.next
	}
	return nil
}

func (hook *OptionFuncHook[T]) Add(fn func(any, T) (bool, error)) *OptionFuncHook[T] {
	return &OptionFuncHook[T]{fn: fn, next: hook}
}

var OptionFuncHooks struct {
	CacheMaxAge     *OptionFuncHook[time.Duration]
	NowGetter       *OptionFuncHook[func() time.Time]
	NoReload        *OptionFuncHook[bool]
	DiagosticLogger *OptionFuncHook[func(string, ...interface{})]
}

func WithCacheMaxAge(d time.Duration) ResolverOptionFunc {
	return func(loader any) error {
		return OptionFuncHooks.CacheMaxAge.Apply(loader, d)
	}
}

func WithNowGetter(fn func() time.Time) ResolverOptionFunc {
	return func(loader any) error {
		return OptionFuncHooks.NowGetter.Apply(loader, fn)
	}
}

func WithNoReload(v bool) ResolverOptionFunc {
	return func(loader any) error {
		return OptionFuncHooks.NoReload.Apply(loader, v)
	}
}

func WithDiagnosticLogger(v func(string, ...interface{})) ResolverOptionFunc {
	return func(loader any) error {
		return OptionFuncHooks.DiagosticLogger.Apply(loader, v)
	}
}
