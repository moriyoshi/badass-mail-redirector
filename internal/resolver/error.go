package resolver

import (
	"context"
	"errors"
)

var (
	ErrNoSuitableAddress         = errors.New("no suitable address found")
	ErrMalformedDNSRecordsDetail = errors.New("DNS response contained records which contain invalid names")
	ErrLameReferral              = errors.New("lame referral")
	ErrCannotUnmarshalDNSMessage = errors.New("cannot unmarshal DNS message")
	ErrCannotMarshalDNSMessage   = errors.New("cannot marshal DNS message")
	ErrServerMisbehaving         = errors.New("server misbehaving")
	ErrInvalidDNSResponse        = errors.New("invalid DNS response")
	ErrNoAnswerFromDNSServer     = errors.New("no answer from DNS server")

	// errServerTemporarilyMisbehaving is like errServerMisbehaving, except
	// that when it gets translated to a DNSError, the IsTemporary field
	// gets set to true.
	ErrServerTemporarilyMisbehaving = &temporaryError{"server misbehaving"}
	ErrCanceled                     = &canceledError{}
	ErrTimeout                      = &timeoutError{}
	ErrNoSuchHost                   = &notFoundError{"no such host"}
)

var hexDigit = "0123456789abcdef"

// canceledError lets us return the same error string we have always
// returned, while still being Is context.Canceled.
type canceledError struct{}

func (canceledError) Error() string { return "operation was canceled" }

func (canceledError) Is(err error) bool { return err == context.Canceled }

// errTimeout exists to return the historical "i/o timeout" string
// for context.DeadlineExceeded. See mapErr.
// It is also used when Dialer.Deadline is exceeded.
// error.Is(errTimeout, context.DeadlineExceeded) returns true.
//
// TODO(iant): We could consider changing this to os.ErrDeadlineExceeded
// in the future, if we make
//
//	errors.Is(os.ErrDeadlineExceeded, context.DeadlineExceeded)
//
// return true.

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (e *timeoutError) Is(err error) bool {
	return err == context.DeadlineExceeded
}

// mapErr maps from the context errors to the historical internal net
// error values.
func mapErr(err error) error {
	switch err {
	case context.Canceled:
		return ErrCanceled
	case context.DeadlineExceeded:
		return ErrTimeout
	default:
		return err
	}
}

// notFoundError is a special error understood by the newDNSError function,
// which causes a creation of a DNSError with IsNotFound field set to true.
type notFoundError struct{ s string }

func (e *notFoundError) Error() string { return e.s }

// temporaryError is an error type that implements the [Error] interface.
// It returns true from the Temporary method.
type temporaryError struct{ s string }

func (e *temporaryError) Error() string   { return e.s }
func (e *temporaryError) Temporary() bool { return true }
func (e *temporaryError) Timeout() bool   { return false }
