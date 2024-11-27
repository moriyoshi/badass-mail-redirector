package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/alecthomas/kong"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	badass "github.com/moriyoshi/badass-mail-redirector"
	"github.com/moriyoshi/badass-mail-redirector/internal/resolver"
	"github.com/moriyoshi/badass-mail-redirector/redirector"
	"github.com/moriyoshi/badass-mail-redirector/smtpclient"
	"github.com/moriyoshi/badass-mail-redirector/types"
)

func loadServerCertificate(certFile string, keyFile string, passphrase string) (*tls.Config, error) {
	var certPEMBlock, keyPEMBlock *pem.Block

	{
		b, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		for {
			var block *pem.Block
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certPEMBlock = block
			}
			if strings.HasSuffix(block.Type, "PRIVATE KEY") {
				keyPEMBlock = block
			}
		}
	}
	if certPEMBlock == nil {
		return nil, fmt.Errorf("no certificate found in %s", certFile)
	}
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		keyPEMBlock, _ = pem.Decode(b)
		if !strings.HasSuffix(keyPEMBlock.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("no private key found in %s", keyFile)
		}
	} else if keyPEMBlock == nil {
		return nil, fmt.Errorf("no key found in %s and no key file is specified", certFile)
	}

	if passphrase != "" {
		b, err := x509.DecryptPEMBlock(keyPEMBlock, []byte(passphrase))
		if err != nil {
			return nil, err
		}
		keyPEMBlock.Bytes = b
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certPEMBlock), pem.EncodeToMemory(keyPEMBlock))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func loadCABundle(certBundle string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	b, err := os.ReadFile(certBundle)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("failed to load CA bundle from %s", certBundle)
	}
	return pool, nil
}

type CLI struct {
	Bind                  string        `name:"bind" help:"Address and port to listen on." env:"BADASS_BIND" default:"[::0]:60025"`
	BindImplicitTLS       string        `name:"bind-implicit-tls" help:"Address and port to listen on, for implicit TLS." env:"BADASS_BIND_IMPLICIT_TLS" default:"[::0]:60465"`
	Certificate           string        `name:"certificate" help:"Path to the certificate file." env:"BADASS_CERTIFICATE" optional:""`
	PrivateKey            string        `name:"private-key" help:"Path to the private key file." env:"BADASS_PRIVATE_KEY" optional:""`
	Passphrase            string        `name:"passphrase" help:"Passphrase for the private key file." env:"BADASS_PASSPHRASE" optional:""`
	CABundle              string        `name:"ca-bundle" help:"Path to the CA bundle file for SMTP client." env:"BADASS_CA_BUNDLE" optional:""`
	Hostname              string        `name:"hostname" help:"Host name to be used in the SMTP banner." env:"BADASS_HOSTNAME" optional:""`
	VerifySpf             bool          `name:"verify-spf" help:"Verify SPF records." env:"BADASS_VERIFY_SPF" default:"true"`
	VerifyDKIM            bool          `name:"verify-dkim" help:"Verify DKIM signatures." env:"BADASS_VERIFY_DKIM" default:"true"`
	PermissiveLocalPart   bool          `name:"permissive-local-part" help:"Allow local parts that are not compliant with RFC 5322." env:"BADASS_PERMISSIVE_LOCAL_PART" default:"false"`
	LogLevel              slog.Level    `name:"log-level" help:"Log level." env:"BADASS_LOG_LEVEL" default:"INFO" enum:"DEBUG,INFO,WARN,ERROR"`
	RedirectionRules      string        `name:"redirection-rules" help:"Path to the redirection rules file." env:"BADASS_REDIRECTION_RULES" default:"redirection-rules.yaml"`
	NextHop               string        `name:"next-hop" help:"Host name / port pair to be used as the next hop." env:"BADASS_NEXT_HOP"`
	NextHopImplicitTLS    bool          `name:"next-hop-implicit-tls" help:"Use implicit TLS for the next hop." env:"BADASS_NEXT_HOP_IMPLICIT_TLS" default:"false"`
	Nameservers           []string      `name:"nameservers" help:"DNS server to use for resolving." env:"BADASS_NAMESERVERS"`
	SMTPConnectionTimeout time.Duration `name:"smtp-connection-timeout" help:"Connection timeout for outbound SMTP connections" env:"BADASS_SMTP_CONNECTION_TIMEOUT" default:"60s"`
}

func (CLI *CLI) initLogger(*kong.Context) *slog.Logger {
	var handler slog.Handler
	if isatty.IsTerminal(os.Stdout.Fd()) {
		handler = tint.NewHandler(colorable.NewColorable(os.Stderr), &tint.Options{Level: CLI.LogLevel})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: CLI.LogLevel})
	}
	return slog.New(handler)
}

func (CLI *CLI) initResolver(kongCtx *kong.Context, logger *slog.Logger) spf.DNSResolver {
	var res spf.DNSResolver
	if len(CLI.Nameservers) > 0 {
		var err error
		dnsConf := resolver.DefaultConfig()
		servers := make([]string, len(CLI.Nameservers))
		copy(servers, CLI.Nameservers)
		for i := range servers {
			var host, port string
			_, _, err := net.SplitHostPort(servers[i])
			if err != nil {
				host, port, err = net.SplitHostPort(servers[i] + ":53")
				if err != nil {
					kongCtx.FatalIfErrorf(fmt.Errorf("invalid DNS server address: %s", servers[i]))
				}
				servers[i] = net.JoinHostPort(host, port)
			}
		}
		dnsConf.Servers = servers
		res, err = resolver.NewResolver(resolver.WithStaticDNSConfig(&dnsConf))
		logger.Info("with custom DNS servers", slog.Any("servers", servers))
		if err != nil {
			kongCtx.FatalIfErrorf(err)
		}
	} else {
		res = &net.Resolver{}
	}
	return res
}

func (CLI *CLI) initRedirector(kongCtx *kong.Context, logger *slog.Logger) *redirector.Redirector {
	redirector, err := redirector.NewRedirectorFromYAMLFile(
		CLI.RedirectionRules,
		redirector.WithPermissiveLocalPart(CLI.PermissiveLocalPart),
		redirector.WithLogger(logger),
	)
	if err != nil {
		kongCtx.FatalIfErrorf(err)
	}
	return redirector
}

func (CLI *CLI) initClientTLSConfig(kongCtx *kong.Context, logger *slog.Logger) *tls.Config {
	clientTLSConfig := new(tls.Config)
	if CLI.CABundle != "" {
		logger.Info("loading CA bundle", slog.String("path", CLI.CABundle))
		caPool, err := loadCABundle(CLI.CABundle)
		if err != nil {
			kongCtx.FatalIfErrorf(err)
		}
		clientTLSConfig.RootCAs = caPool
	}
	return clientTLSConfig
}

func (CLI *CLI) initSMTPClient(kongCtx *kong.Context, logger *slog.Logger, res spf.DNSResolver, clientTLSConfig *tls.Config) *smtpclient.SensibleSMTPClient {
	smtpClient, err := smtpclient.NewSensibleSMTPClient(
		CLI.Hostname,
		smtpclient.WithLogger(logger),
		smtpclient.WithResolver(res),
		smtpclient.WithTLSConfig(clientTLSConfig),
		smtpclient.WithConnTimeout(CLI.SMTPConnectionTimeout),
		smtpclient.WithNextHop(CLI.NextHop),
		smtpclient.WithNextHopImplicitTLS(CLI.NextHopImplicitTLS),
	)
	if err != nil {
		kongCtx.FatalIfErrorf(err)
	}
	return smtpClient
}

func (CLI *CLI) initServer(kongCtx *kong.Context, logger *slog.Logger, res spf.DNSResolver, redirector *redirector.Redirector, smtpClient *smtpclient.SensibleSMTPClient) *badass.Server {
	options := []badass.OptionFunc{
		badass.WithSPFVerification(CLI.VerifySpf),
		badass.WithDKIMVerification(CLI.VerifyDKIM),
		badass.WithLogger(logger),
		badass.WithResolver(res),
	}
	if CLI.Hostname != "" {
		options = append(options, badass.WithHostname(CLI.Hostname))
	}
	if CLI.Certificate != "" {
		serverTLSConfig, err := loadServerCertificate(CLI.Certificate, CLI.PrivateKey, CLI.Passphrase)
		if err != nil {
			kongCtx.FatalIfErrorf(err)
		}
		options = append(options, badass.WithTLSConfig(serverTLSConfig))
	}
	server, err := badass.NewServer(
		CLI.Bind,
		CLI.BindImplicitTLS,
		redirector,
		func(ctx context.Context, domain string, mails []types.Mail) error {
			_mails := make([]smtpclient.Mail, len(mails))
			for i, mail := range mails {
				_mails[i] = mail
			}
			return smtpClient.SendMails(ctx, domain, _mails)
		},
		options...,
	)
	if err != nil {
		kongCtx.FatalIfErrorf(err)
	}
	return server
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	var CLI CLI
	kongCtx := kong.Parse(&CLI)
	logger := CLI.initLogger(kongCtx)
	res := CLI.initResolver(kongCtx, logger)
	redirector := CLI.initRedirector(kongCtx, logger)
	clientTLSConfig := CLI.initClientTLSConfig(kongCtx, logger)
	smtpClient := CLI.initSMTPClient(kongCtx, logger, res, clientTLSConfig)
	server := CLI.initServer(kongCtx, logger, res, redirector, smtpClient)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		count := 0
	outer:
		for {
			select {
			case <-ctx.Done():
				break outer
			case <-sigChan:
				count += 1
				if count == 1 {
					kongCtx.Printf("Received SIGINT, shutting down...")
					err := server.Shutdown(ctx)
					if err != nil {
						kongCtx.FatalIfErrorf(err)
					}
				} else {
					kongCtx.Printf("Received SIGINT again, forcing shutdown...")
					cancel()
				}
			}
		}
	}()
	err := server.Serve(ctx)
	if err != nil {
		kongCtx.FatalIfErrorf(err)
	}
}
