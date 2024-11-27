package badass

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/mail"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/moriyoshi/badass-mail-redirector/smtpclient"
	"github.com/moriyoshi/badass-mail-redirector/types"
)

type mockRedirector struct{}

func (*mockRedirector) TryRedirect(m types.Mail, _ *types.ReceptionDescriptor) (bool, types.Mail, string, error) {
	return true, m, "example.com", nil
}

type mockOutlet struct {
	domain string
	mails  []types.Mail
}

func (o *mockOutlet) handle(_ context.Context, domain string, mails []types.Mail) error {
	o.domain = domain
	o.mails = mails
	return nil
}

type mockResolver struct {
	addr *net.TCPAddr
}

func (r *mockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil
}

func (r *mockResolver) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: r.addr.IP, Zone: r.addr.Zone}}, nil
}

func (r *mockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, nil
}

func (r *mockResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, nil
}

func TestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := &mockOutlet{}
	s, err := NewServer(
		"localhost:0",
		"localhost:0",
		&mockRedirector{},
		o.handle,
	)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	go func() {
		assert.NoError(t, s.Serve(ctx))
		s.Shutdown(ctx)
	}()
	select {
	case <-ctx.Done():
		t.FailNow()
	case <-s.Ready():
	}
	{
		sc, err := smtpclient.NewSensibleSMTPClient(
			"sender.example.com",
			smtpclient.WithResolver(&mockResolver{s.server.l.Addr().(*net.TCPAddr)}),
			smtpclient.WithPorts(s.server.l.Addr().(*net.TCPAddr).Port),
		)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		err = sc.SendMails(ctx, "example.com", []smtpclient.Mail{
			types.NewMail("foo@example.com", "bar@example.com", []byte("Subject: hello\r\n\r\nHello, world!\r\n")),
		})
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(t, "example.com", o.domain)
		if assert.Len(t, o.mails, 1) {
			assert.Equal(t, "foo@example.com", o.mails[0].Sender())
			assert.Equal(t, "bar@example.com", o.mails[0].Recipient())
			m, err := mail.ReadMessage(bytes.NewReader(o.mails[0].Data()))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			assert.Equal(t, "hello", m.Header.Get("Subject"))
			b, err := io.ReadAll(m.Body)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			assert.Equal(t, []byte("Hello, world!\r\n"), b)
		}
	}
}
