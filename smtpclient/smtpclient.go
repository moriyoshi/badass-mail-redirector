package smtpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"slices"
	"strconv"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/moriyoshi/badass-mail-redirector/internal/logging"
)

type SensibleSMTPClient struct {
	resolver                spf.DNSResolver
	resolutionStats         map[string]map[string]int
	connTimeout             time.Duration
	logger                  *slog.Logger
	resolutionRetryCount    int
	resolutionRetryInterval time.Duration
	ports                   []int
	hostname                string
	nextHop                 string
	nextHopImplicitTLS      bool
	tlsConfig               *tls.Config
}

type hostPrefCount struct {
	host  string
	pref  int
	count int
}

func (client *SensibleSMTPClient) lookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	resolutionRetryInterval := client.resolutionRetryInterval
	for i := 0; i < client.resolutionRetryCount; i++ {
		retval, err := client.resolver.LookupMX(ctx, name)
		if err == nil {
			return retval, nil
		}
		if err, ok := err.(net.Error); ok && err.Temporary() {
			time.Sleep(resolutionRetryInterval)
			resolutionRetryInterval *= 2
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("failed to lookup MX records for %s: retry count exceeded", name)
}

func (client *SensibleSMTPClient) lookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	resolutionRetryInterval := client.resolutionRetryInterval
	for i := 0; i < client.resolutionRetryCount; i++ {
		retval, err := client.resolver.LookupIPAddr(ctx, name)
		if err == nil {
			return retval, nil
		}
		if err, ok := err.(net.Error); ok && err.Temporary() {
			time.Sleep(resolutionRetryInterval)
			resolutionRetryInterval *= 2
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("failed to lookup A/AAAA records for %s: retry count exceeded", name)
}

const (
	portSMTP            = 25
	portSMTPImplicitTLS = 465
)

var defaultPorts = [2]int{portSMTP, portSMTPImplicitTLS}

func (client *SensibleSMTPClient) connectToHost(ctx context.Context, domain string) (string, net.Conn, error) {
	logger := client.logger.With(slog.String("domain", domain))

	hosts, err := client.lookupMX(ctx, domain)
	if err != nil {
		return "", nil, err
	}

	statsForDomain := client.resolutionStats[domain]
	if statsForDomain == nil {
		statsForDomain = make(map[string]int)
		client.resolutionStats[domain] = statsForDomain
	}

	triples := make([]hostPrefCount, len(hosts))
	for i, host := range hosts {
		if _, ok := statsForDomain[host.Host]; !ok {
			statsForDomain[host.Host] = 0
		}
		triples[i] = hostPrefCount{host.Host, int(host.Pref), statsForDomain[host.Host]}
	}

	slices.SortFunc(triples, func(i, j hostPrefCount) int {
		if i.pref == j.pref {
			return i.count - j.count
		}
		return j.pref - i.pref
	})

	var conn net.Conn
	var selectedHost string
	var port int
	for _, triple := range triples {
		logger.Debug("looking up host", slog.String("host", triple.host))
		addrs, err := client.lookupIPAddr(ctx, triple.host)
		logger := logger.With(slog.String("host", triple.host))
		if err != nil {
			logger.WarnContext(ctx, "failed to lookup host", slog.Any("error", err))
			continue
		}
		spreadTimeout := (client.connTimeout + time.Duration(len(addrs)*len(client.ports)-1)) / time.Duration(len(addrs)+len(client.ports))

	outer:
		for _, _port := range client.ports {
			for _, addr := range addrs {
				hostPort := net.JoinHostPort(addr.String(), strconv.Itoa(_port))
				logger.Debug("connecting to host", slog.String("host", addr.String()), slog.Int("port", _port))
				conn, err = (&net.Dialer{
					Timeout: spreadTimeout,
				}).DialContext(ctx, "tcp", hostPort)
				if err == nil {
					port = _port
					break outer
				}
				logger.WarnContext(ctx, "failed to connect", slog.String("address", hostPort), slog.Any("error", err))
			}
		}
		if err == nil {
			selectedHost = triple.host
			break
		}
		logger.WarnContext(ctx, "failed to connect", slog.Any("error", err))
	}

	if conn == nil {
		return "", nil, fmt.Errorf("no hosts available for %s", domain)
	}

	// implicit TLS
	if port == portSMTPImplicitTLS {
		tlsConfig := client.tlsConfig.Clone()
		tlsConfig.ServerName = selectedHost
		conn = tls.Client(conn, tlsConfig)
	}

	return selectedHost, conn, nil
}

func (client *SensibleSMTPClient) SendMails(ctx context.Context, domain string, mails []Mail) error {
	var host string
	var conn net.Conn
	var err error

	logger := client.logger.With(slog.String("domain", domain))

	if client.nextHop == "" {
		host, conn, err = client.connectToHost(ctx, domain)
	} else {
		host = client.nextHop
		conn, err = (&net.Dialer{
			Timeout: client.connTimeout,
		}).DialContext(ctx, "tcp", host)
		if client.nextHopImplicitTLS {
			tlsConfig := client.tlsConfig.Clone()
			tlsConfig.ServerName = host
			conn = tls.Client(conn, tlsConfig)
		}
	}
	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	for _, mail := range mails {
		logger := logger.With(slog.String("sender", mail.Sender()), slog.Any("recipients", mail.Recipients()))
		if err = c.Hello(client.hostname); err != nil {
			return err
		}
		if ok, _ := c.Extension("STARTTLS"); ok {
			logger.Debug("starttls")
			config := client.tlsConfig.Clone()
			config.ServerName = host
			if err = c.StartTLS(config); err != nil {
				return err
			}
		}
		logger.Debug("mail from")
		if err = c.Mail(mail.Sender()); err != nil {
			return err
		}
		logger.Debug("rcpt to")
		for _, rcpt := range mail.Recipients() {
			if err = c.Rcpt(rcpt); err != nil {
				return err
			}
		}
		logger.Debug("data")
		err = func() error {
			w, err := c.Data()
			if err != nil {
				return err
			}
			defer w.Close()
			_, err = w.Write(mail.Data())
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	err = c.Quit()
	if err != nil {
		return err
	}
	return nil
}

type SensibleSMTPClientOptionFunc func(*SensibleSMTPClient) (*SensibleSMTPClient, error)

func WithTLSConfig(config *tls.Config) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.tlsConfig = config
		return client, nil
	}
}

func WithResolver(resolver spf.DNSResolver) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.resolver = resolver
		return client, nil
	}
}

func WithLogger(logger *slog.Logger) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		if logger == nil {
			logger = slog.New(logging.BlackholeHandler{})
		}
		client.logger = logger
		return client, nil
	}
}

func WithConnTimeout(timeout time.Duration) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.connTimeout = timeout
		return client, nil
	}
}

func WithResolutionRetryCount(count int) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.resolutionRetryCount = count
		return client, nil
	}
}

func WithResolutionRetryInterval(interval time.Duration) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.resolutionRetryInterval = interval
		return client, nil
	}
}

func WithImplicitTLSEnabled(enabled bool) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		if enabled {
			client.ports = defaultPorts[:]
		} else {
			client.ports = defaultPorts[:1]
		}
		return client, nil
	}
}

func WithPorts(ports ...int) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.ports = ports
		return client, nil
	}
}

func WithNextHop(nextHop string) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.nextHop = nextHop
		return client, nil
	}
}

func WithNextHopImplicitTLS(enabled bool) SensibleSMTPClientOptionFunc {
	return func(client *SensibleSMTPClient) (*SensibleSMTPClient, error) {
		client.nextHopImplicitTLS = enabled
		return client, nil
	}
}

func NewSensibleSMTPClient(hostname string, options ...SensibleSMTPClientOptionFunc) (*SensibleSMTPClient, error) {
	client := &SensibleSMTPClient{
		resolver:                &net.Resolver{},
		resolutionStats:         make(map[string]map[string]int),
		connTimeout:             5 * time.Second,
		logger:                  slog.New(logging.BlackholeHandler{}),
		resolutionRetryCount:    3,
		resolutionRetryInterval: 1 * time.Second,
		ports:                   defaultPorts[:1],
		hostname:                hostname,
	}
	for _, option := range options {
		var err error
		client, err = option(client)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}
