package badass

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/mhale/smtpd"
	"golang.org/x/sync/errgroup"

	"github.com/moriyoshi/badass-mail-redirector/redirector"
	"github.com/moriyoshi/badass-mail-redirector/smtpclient"
)

const appName = "badass"

type serverListenerPair struct {
	S *smtpd.Server
	L *listenerWithContext
}

func (pair *serverListenerPair) Valid() bool {
	return pair.S != nil
}

type Mail = smtpclient.Mail

type Outlet func(ctx context.Context, domain string, mails []Mail) error

type Server struct {
	addr           string
	implicitAddr   string
	appname        string
	hostname       string
	resolver       spf.DNSResolver
	verifySPF      bool
	verifyDKIM     bool
	tlsConfig      *tls.Config
	logger         *slog.Logger
	server         serverListenerPair
	serverImplicit serverListenerPair
	redirector     *redirector.Redirector
	outlet         Outlet
}

type OptionFunc func(s *Server) error

func WithHostname(hostname string) OptionFunc {
	return func(s *Server) error {
		s.hostname = hostname
		return nil
	}
}

func WithTLSConfig(tlsConfig *tls.Config) OptionFunc {
	return func(s *Server) error {
		s.tlsConfig = tlsConfig
		return nil
	}
}

func WithResolver(r spf.DNSResolver) OptionFunc {
	return func(s *Server) error {
		s.resolver = r
		return nil
	}
}

func WithSPFVerification(enabled bool) OptionFunc {
	return func(s *Server) error {
		s.verifySPF = enabled
		return nil
	}
}

func WithDKIMVerification(enabled bool) OptionFunc {
	return func(s *Server) error {
		s.verifyDKIM = enabled
		return nil
	}
}

func WithLogger(logger *slog.Logger) OptionFunc {
	return func(s *Server) error {
		s.logger = logger
		return nil
	}
}

func (s *Server) newSmtpdServerProto() *smtpd.Server {
	return &smtpd.Server{
		Appname:   s.appname,
		Hostname:  s.hostname,
		TLSConfig: s.tlsConfig,
	}
}

func NewServer(bind, bindImplicitTLS string, redirector *redirector.Redirector, outlet Outlet, options ...OptionFunc) (*Server, error) {
	s := &Server{
		addr:         bind,
		implicitAddr: bindImplicitTLS,
		appname:      appName,
		hostname:     "",
		resolver:     &net.Resolver{},
		redirector:   redirector,
		outlet:       outlet,
	}
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}
	s.server.S = s.newSmtpdServerProto()
	s.server.S.Addr = s.addr
	if s.implicitAddr != "" {
		s.serverImplicit.S = s.newSmtpdServerProto()
		s.serverImplicit.S.Addr = s.implicitAddr
		s.serverImplicit.S.TLSListener = true
	}
	return s, nil
}

func ipPart(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	case *net.IPAddr:
		return addr.IP
	default:
		return nil
	}
}

func (s *Server) handlerInner(ctx context.Context, origin net.Addr, from string, to []string, data []byte) error {
	logger := s.logger.With(slog.String("origin", origin.String()), slog.String("from", from), slog.Any("to", to), slog.Int("size", len(data)))
	if s.verifySPF {
		result, err := spf.CheckHostWithSender(
			ipPart(origin),
			"",
			from,
			spf.WithResolver(s.resolver),
			spf.WithContext(ctx),
			spf.WithTraceFunc(func(s string, args ...interface{}) {
				logger.Debug("spf trace", slog.String("text", fmt.Sprintf(s, args...)))
			}),
		)
		if err != nil {
			switch err {
			case spf.ErrMatchedAll, spf.ErrMatchedA, spf.ErrMatchedIP, spf.ErrMatchedMX, spf.ErrMatchedPTR, spf.ErrMatchedExists:
				break
			default:
				return fmt.Errorf("error occurred during verifying SPF record: %w", err)
			}
		}
		if result == spf.Fail {
			return fmt.Errorf("SPF fail")
		}
	}
	if s.verifyDKIM {
		b := bytes.NewReader(data)
		results, err := dkim.VerifyWithOptions(
			b,
			&dkim.VerifyOptions{
				LookupTXT: func(domain string) ([]string, error) {
					return s.resolver.LookupTXT(ctx, domain)
				},
			},
		)
		if err != nil {
			return fmt.Errorf("error occurred during DKIM verification: %w", err)
		}
		for _, v := range results {
			if v.Err != nil {
				return fmt.Errorf("DKIM verification failed: %w", err)
			}
		}
	}
	redirected := map[string]*[]Mail{}
	for _, rcpt := range to {
		ok, m, domain, err := s.redirector.TryRedirect(
			redirector.NewMail(from, rcpt, data),
			&redirector.ReceptionDescriptor{
				SenderHost: origin.String(),
				Host:       s.hostname,
				Protocol:   "ESMTP", // FIXME
				ID:         "0",
				Timestamp:  time.Now(),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to redirect: %w", err)
		}
		if ok {
			mailsPtr := redirected[domain]
			if mailsPtr == nil {
				mailsPtr = new([]Mail)
				redirected[domain] = mailsPtr
				*mailsPtr = make([]Mail, 0, 1)
			}
			*mailsPtr = append(*mailsPtr, m)
		}
	}
	if len(redirected) > 0 {
		var eg errgroup.Group
		for domain, mails := range redirected {
			eg.Go(func() error {
				return s.outlet(ctx, domain, *mails)
			})
		}
		err := eg.Wait()
		if err != nil {
			return fmt.Errorf("failed to send mails: %w", err)
		}
	}
	return nil
}

func (s *Server) handler(ctx context.Context, origin net.Addr, from string, to []string, data []byte) error {
	err := s.handlerInner(ctx, origin, from, to, data)
	if err != nil {
		s.logger.Error("failed to handle mail", slog.Any("error", err))
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	eg, innerCtx := errgroup.WithContext(ctx)
	if s.server.Valid() {
		s.server.L.Close()
		eg.Go(func() error { return s.server.S.Shutdown(innerCtx) })
	}
	if s.serverImplicit.Valid() {
		s.serverImplicit.L.Close()
		eg.Go(func() error { return s.serverImplicit.S.Shutdown(innerCtx) })
	}
	return eg.Wait()
}

type listenerWithContext struct {
	net.Listener
	ctx    context.Context
	cancel context.CancelFunc
}

func (l *listenerWithContext) Context() context.Context {
	return l.ctx
}

func (l *listenerWithContext) Close() error {
	err := l.Listener.Close()
	l.cancel()
	return err
}

func (l *listenerWithContext) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			l.cancel()
		}
	}
	return conn, err
}
func (l *listenerWithContext) Addr() net.Addr {
	return l.Listener.Addr()
}

func wrapListener(ctx context.Context, ln net.Listener) *listenerWithContext {
	ctx, cancel := context.WithCancel(ctx)
	inner := &listenerWithContext{
		Listener: ln,
		ctx:      ctx,
		cancel:   cancel,
	}
	go func() {
		<-ctx.Done()
		inner.Close()
	}()
	return inner
}

func listenAndServe(
	ctx context.Context,
	s *serverListenerPair,
	handler func(context.Context, net.Addr, string, []string, []byte) error,
) error {
	if s.S.Appname == "" {
		s.S.Appname = "smtpd"
	}
	if s.S.Hostname == "" {
		s.S.Hostname, _ = os.Hostname()
	}
	if s.S.Timeout == 0 {
		s.S.Timeout = 5 * time.Minute
	}

	// If TLSListener is enabled, listen for TLS connections only.
	ln, err := net.Listen("tcp", s.S.Addr)
	if err != nil {
		return err
	}
	s.L = wrapListener(ctx, ln)
	if s.S.TLSConfig != nil && s.S.TLSListener {
		ln = tls.NewListener(s.L, s.S.TLSConfig)
	}
	s.S.Handler = func(origin net.Addr, from string, to []string, data []byte) error {
		return handler(ctx, origin, from, to, data)
	}
	return s.S.Serve(ln)
}

func (s *Server) Serve(ctx context.Context) error {
	eg, innerCtx := errgroup.WithContext(ctx)
	if s.server.Valid() {
		go func() {
			<-innerCtx.Done()
			s.server.L.Close()
		}()
		eg.Go(func() error {
			err := listenAndServe(innerCtx, &s.server, s.handler)
			if err != nil && errors.Is(err, net.ErrClosed) {
				err = nil
			}
			return err
		})
	}
	if s.serverImplicit.Valid() {
		go func() {
			<-innerCtx.Done()
			s.serverImplicit.L.Close()
		}()
		eg.Go(func() error {
			err := listenAndServe(innerCtx, &s.serverImplicit, s.handler)
			if err != nil && errors.Is(err, net.ErrClosed) {
				err = nil
			}
			return err
		})
	}
	return eg.Wait()
}
