package types

import (
	"time"
)

type ReceptionDescriptor struct {
	SenderHost string
	Host       string
	Protocol   string
	ID         string
	Timestamp  time.Time
}
