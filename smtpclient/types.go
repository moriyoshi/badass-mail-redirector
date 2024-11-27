package smtpclient

type Mail interface {
	Sender() string
	Recipients() []string
	Data() []byte
}
