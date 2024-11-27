package types

// Redirector handles redirection of mail.
// The first return value indicates whether the redirection was successful.
// The second return value is the Mail rewritten.
// The third return value is the domain name of the redirected mail.
// The non-nil value of the fourth return value indicates an error.
type Redirector interface {
	TryRedirect(Mail, *ReceptionDescriptor) (bool, Mail, string, error)
}
