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

	"github.com/moriyoshi/badass-mail-redirector/internal/logging"
	"github.com/moriyoshi/badass-mail-redirector/types"
)

const appName = "badass"

type serverListenerPair struct {
	s         *smtpd.Server
	readyChan chan *serverListenerPair
	l         net.Listener
}

func (pair *serverListenerPair) Valid() bool {
	return pair.s != nil
}

func (pair *serverListenerPair) Ready() <-chan *serverListenerPair {
	return pair.readyChan
}

func (pair *serverListenerPair) setListener(l net.Listener) {
	pair.l = l
	pair.readyChan <- pair
}

func newServerListenerPair(s *smtpd.Server) serverListenerPair {
	return serverListenerPair{s: s, readyChan: make(chan *serverListenerPair)}
}

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
	redirector     types.Redirector
	outlet         types.Outlet
	readyChan      chan struct{}
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

func (s *Server) newSmtpdServerProto(addr string, tlsListener bool) *smtpd.Server {
	return &smtpd.Server{
		Appname:     s.appname,
		Hostname:    s.hostname,
		TLSConfig:   s.tlsConfig,
		Addr:        addr,
		TLSListener: tlsListener,
	}
}

func NewServer(bind, bindImplicitTLS string, redirector types.Redirector, outlet types.Outlet, options ...OptionFunc) (*Server, error) {
	s := &Server{
		addr:         bind,
		implicitAddr: bindImplicitTLS,
		appname:      appName,
		hostname:     "",
		resolver:     &net.Resolver{},
		logger:       slog.New(logging.BlackholeHandler{}),
		redirector:   redirector,
		outlet:       outlet,
		readyChan:    make(chan struct{}),
	}
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}
	s.server = newServerListenerPair(s.newSmtpdServerProto(s.addr, false))
	if s.implicitAddr != "" {
		s.serverImplicit = newServerListenerPair(s.newSmtpdServerProto(s.implicitAddr, true))
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
	redirected := map[string]*[]types.Mail{}
	for _, rcpt := range to {
		ok, m, domain, err := s.redirector.TryRedirect(
			types.NewMail(from, rcpt, data),
			&types.ReceptionDescriptor{
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
				mailsPtr = new([]types.Mail)
				redirected[domain] = mailsPtr
				*mailsPtr = make([]types.Mail, 0, 1)
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

func (s *Server) rcptHandlerInner(ctx context.Context, logger *slog.Logger, origin net.Addr, from string, to string) (bool, error) {
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
				return false, fmt.Errorf("error occurred during verifying SPF record: %w", err)
			}
		}
		if result == spf.Fail {
			return false, fmt.Errorf("SPF fail")
		}
	}
	ok, _, _, err := s.redirector.TryRedirect(
		types.NewMail(from, to, nil),
		&types.ReceptionDescriptor{
			SenderHost: origin.String(),
			Host:       s.hostname,
			Protocol:   "ESMTP", // FIXME
			ID:         "0",
			Timestamp:  time.Now(),
		},
	)
	if err != nil {
		return false, fmt.Errorf("failed to redirect: %w", err)
	}
	return ok, nil
}

func (s *Server) handler(ctx context.Context, origin net.Addr, from string, to []string, data []byte) error {
	logger := s.logger.With(slog.String("origin", origin.String()), slog.String("from", from), slog.Any("to", to), slog.Any("size", len(data)))
	err := s.handlerInner(ctx, origin, from, to, data)
	if err != nil {
		logger.Error("failed to handle mail", slog.Any("error", err))
	}
	return err
}

func (s *Server) rcptHandler(ctx context.Context, origin net.Addr, from string, to string) bool {
	logger := s.logger.With(slog.String("origin", origin.String()), slog.String("from", from), slog.String("to", to))
	ok, err := s.rcptHandlerInner(ctx, logger, origin, from, to)
	if err != nil {
		logger.Error("failed to handle mail", slog.Any("error", err))
		return false
	}
	return ok
}

func (s *Server) Shutdown(ctx context.Context) error {
	eg, innerCtx := errgroup.WithContext(ctx)
	if s.server.Valid() {
		s.server.l.Close()
		eg.Go(func() error { return s.server.s.Shutdown(innerCtx) })
	}
	if s.serverImplicit.Valid() {
		s.serverImplicit.l.Close()
		eg.Go(func() error { return s.serverImplicit.s.Shutdown(innerCtx) })
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

func (s *Server) listenAndServe(
	ctx context.Context,
	slp *serverListenerPair,
) error {
	if slp.s.Appname == "" {
		slp.s.Appname = "smtpd"
	}
	if slp.s.Hostname == "" {
		slp.s.Hostname, _ = os.Hostname()
	}
	if slp.s.Timeout == 0 {
		slp.s.Timeout = 5 * time.Minute
	}

	// If TLSListener is enabled, listen for TLS connections only.
	ln, err := net.Listen("tcp", slp.s.Addr)
	if err != nil {
		return err
	}
	ln = wrapListener(ctx, ln)
	if slp.s.TLSConfig != nil && slp.s.TLSListener {
		ln = tls.NewListener(ln, slp.s.TLSConfig)
	}
	slp.s.Handler = func(origin net.Addr, from string, to []string, data []byte) error {
		return s.handler(ctx, origin, from, to, data)
	}
	slp.s.HandlerRcpt = func(origin net.Addr, from string, to string) bool {
		return s.rcptHandler(ctx, origin, from, to)
	}
	slp.setListener(ln)
	return slp.s.Serve(ln)
}

func (s *Server) Ready() <-chan struct{} {
	return s.readyChan
}

func (s *Server) Serve(ctx context.Context) error {
	eg, innerCtx := errgroup.WithContext(ctx)
	readyChans := make([]<-chan *serverListenerPair, 0, 2)
	if s.server.Valid() {
		go func() {
			<-innerCtx.Done()
			s.server.l.Close()
		}()
		eg.Go(func() error {
			err := s.listenAndServe(innerCtx, &s.server)
			if err != nil && errors.Is(err, net.ErrClosed) {
				err = nil
			}
			return err
		})
		readyChans = append(readyChans, s.server.Ready())
	}
	if s.serverImplicit.Valid() {
		go func() {
			<-innerCtx.Done()
			s.serverImplicit.l.Close()
		}()
		eg.Go(func() error {
			err := s.listenAndServe(innerCtx, &s.serverImplicit)
			if err != nil && errors.Is(err, net.ErrClosed) {
				err = nil
			}
			return err
		})
		readyChans = append(readyChans, s.serverImplicit.Ready())
	}
	readyServers := make([]*serverListenerPair, 0, 2)
outer:
	for _, readyChan := range readyChans {
		select {
		case <-innerCtx.Done():
			for _, slp := range readyServers {
				err := slp.l.Close()
				if err != nil {
					s.logger.Warn("failed to close listener", slog.Any("error", err))
				}
				// XXX: this may race with Serve()
				err = slp.s.Close()
				if err != nil {
					s.logger.Warn("failed to close server", slog.Any("error", err))
				}
			}
			break outer
		case s := <-readyChan:
			readyServers = append(readyServers, s)
		}
	}
	close(s.readyChan)
	return eg.Wait()
}
