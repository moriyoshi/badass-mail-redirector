package redirector

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/textproto"
	"regexp"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v3"

	"github.com/moriyoshi/badass-mail-redirector/types"
)

func TestRedirectionRuleUnmarshal(t *testing.T) {
	t.Setenv("foo", "FOO")
	{
		var rr RedirectionRules
		err := json.Unmarshal([]byte(`[{"match": "foo${env.foo}", "substitution": "${env.foo}"}]`), &rr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Len(t, rr, 1)
		assert.Equal(t, rr[0].R.String(), "fooFOO")
		assert.Equal(t, rr[0].S, "FOO")
	}
	{
		var rr RedirectionRules
		err := json.Unmarshal([]byte(`{"foo${env.foo}": "${env.foo}"}`), &rr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Len(t, rr, 1)
		assert.Equal(t, rr[0].R.String(), "fooFOO")
		assert.Equal(t, rr[0].S, "FOO")
	}
	{
		var rr RedirectionRules
		err := yaml.Unmarshal([]byte(`[{"match": "foo${env.foo}", "substitution": "${env.foo}"}]`), &rr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Len(t, rr, 1)
		assert.Equal(t, rr[0].R.String(), "fooFOO")
		assert.Equal(t, rr[0].S, "FOO")
	}
	{
		var rr RedirectionRules
		err := yaml.Unmarshal([]byte(`{"foo${env.foo}": "${env.foo}"}]`), &rr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Len(t, rr, 1)
		assert.Equal(t, rr[0].R.String(), "fooFOO")
		assert.Equal(t, rr[0].S, "FOO")
	}
}

func TestRedirector(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRedirector(
		[]RedirectionRule{
			{R: regexp.MustCompile(`foo(?:\+([^@]+))?@example.com`), S: "bar$1@example.com"},
		},
		WithDKIMSignOptions(&dkim.SignOptions{
			Domain:       "example.com",
			Selector:     "selector",
			Identifier:   "",
			Signer:       privKey,
			Hash:         crypto.SHA256,
			HeaderKeys:   []string{"From", "To", "Subject", "Content-Type", "MIME-Version", "Message-ID", "Date"},
			Expiration:   time.Time{},
			QueryMethods: []dkim.QueryMethod{dkim.QueryMethodDNSTXT},
		}),
	)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	ok, rewritten, domain, err := r.TryRedirect(
		types.NewMail(
			"sender@example.com",
			"foo@example.com",
			[]byte("To: foo@example.com, irrelevant@example.com\r\n\r\nHello, World!"),
		),
		&types.ReceptionDescriptor{
			SenderHost: "sender.example.com",
			Host:       "receiver.example.com",
			Protocol:   "ESMTP",
			ID:         "id",
			Timestamp:  time.Unix(0, 0),
		},
	)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	assert.True(t, ok)
	assert.Equal(t, "bar@example.com", rewritten.Recipient())
	assert.Equal(t, "example.com", domain)
	rdr := textproto.NewReader(bufio.NewReader(bytes.NewReader(rewritten.Data())))
	h, err := rdr.ReadMIMEHeader()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	assert.Equal(t, "<bar@example.com>, <irrelevant@example.com>", h.Get("To"))
	v, err := dkim.VerifyWithOptions(bytes.NewReader(rewritten.Data()), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return []string{fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", base64.StdEncoding.EncodeToString(pubKey))}, nil
		},
	})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	assert.NoError(t, v[0].Err)
}
