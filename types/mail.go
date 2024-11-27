package types

type Mail struct {
	sender    string
	recipient string
	data      []byte
}

func NewMail(sender, recipient string, data []byte) Mail {
	return Mail{
		sender:    sender,
		recipient: recipient,
		data:      data,
	}
}

func (m Mail) Sender() string {
	return m.sender
}

func (m Mail) Recipient() string {
	return m.recipient
}

func (m Mail) Recipients() []string {
	return []string{m.recipient}
}

func (m Mail) Data() []byte {
	return m.data
}
