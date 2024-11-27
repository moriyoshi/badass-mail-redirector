package redirector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/moriyoshi/badass-mail-redirector/internal/bufio"
	"github.com/moriyoshi/badass-mail-redirector/internal/expand"
	"github.com/moriyoshi/badass-mail-redirector/internal/logging"
	"github.com/moriyoshi/badass-mail-redirector/internal/rfc5322"
	"github.com/moriyoshi/badass-mail-redirector/internal/rfc5322/address"
	"github.com/moriyoshi/badass-mail-redirector/types"
)

type RegexpSubstition struct {
	R *regexp.Regexp
	S string
}

func (rs RegexpSubstition) Substitute(s string) string {
	return rs.R.ReplaceAllString(s, rs.S)
}

type RedirectionRule RegexpSubstition

func expander(key string) string {
	if strings.HasPrefix(key, "env.") {
		return os.Getenv(key[4:])
	}
	return ""
}

func (rr *RedirectionRule) UnmarshalStructure(v map[string]interface{}) error {
	if match, ok := v["match"].(string); !ok {
		return fmt.Errorf("key 'match' is not a string")
	} else if substitution, ok := v["substitution"].(string); !ok {
		return fmt.Errorf("key 'substitution' is not a string")
	} else {
		match = expand.Expand(match, expander)
		substitution = expand.Expand(substitution, expander)
		r, err := regexp.Compile(match)
		if err != nil {
			return err
		}
		*rr = RedirectionRule{
			R: r,
			S: substitution,
		}
		return nil
	}
}

func (rr *RedirectionRule) UnmarshalJSON(b []byte) error {
	var rule interface{}
	err := json.Unmarshal(b, &rule)
	if err != nil {
		return err
	}

	if rule, ok := rule.(map[string]interface{}); ok {
		return rr.UnmarshalStructure(rule)
	} else {
		return fmt.Errorf("rule is not an object")
	}
}

type RedirectionRules []RedirectionRule

func (rrs *RedirectionRules) UnmarshalJSON(b []byte) error {
	var rules interface{}
	err := json.Unmarshal(b, &rules)
	if err != nil {
		return err
	}
	return rrs.unmarshalInner(rules)
}

func (rrs *RedirectionRules) UnmarshalYAML(n *yaml.Node) error {
	var rules interface{}
	err := n.Decode(&rules)
	if err != nil {
		return err
	}
	return rrs.unmarshalInner(rules)
}

func (rrs *RedirectionRules) unmarshalInner(rules interface{}) error {
	switch rules := rules.(type) {
	case map[string]interface{}:
		_rrs := make([]RedirectionRule, 0, len(rules))
		for match, substitution := range rules {
			if substitution, ok := substitution.(string); !ok {
				return fmt.Errorf("value for key %q is not a string", match)
			} else {
				match = expand.Expand(match, expander)
				substitution = expand.Expand(substitution, expander)
				r, err := regexp.Compile(match)
				if err != nil {
					return err
				}
				_rrs = append(_rrs, RedirectionRule{
					R: r,
					S: substitution,
				})
			}
		}
		*rrs = _rrs
	case []interface{}:
		_rrs := make([]RedirectionRule, 0, len(rules))
		for _, r := range rules {
			if r, ok := r.(map[string]interface{}); !ok {
				return fmt.Errorf("rule is not an object")
			} else {
				var rr RedirectionRule
				err := rr.UnmarshalStructure(r)
				if err != nil {
					return err
				}
				_rrs = append(_rrs, rr)
			}
		}
		*rrs = _rrs
	default:
		return fmt.Errorf("rules is not an object or an array")
	}
	return nil
}

type Redirector struct {
	Rules               RedirectionRules
	permissiveLocalPart bool
	logger              *slog.Logger
	parser              *address.AddressParser
	renderer            *address.AddressRenderer
	dkimSignOptions     *dkim.SignOptions
}

type RedirectorOptionFunc func(*Redirector) (*Redirector, error)

func WithLogger(logger *slog.Logger) RedirectorOptionFunc {
	return func(r *Redirector) (*Redirector, error) {
		if logger == nil {
			logger = slog.New(logging.BlackholeHandler{})
		}
		r.logger = logger
		return r, nil
	}
}

func WithPermissiveLocalPart(enabled bool) RedirectorOptionFunc {
	return func(r *Redirector) (*Redirector, error) {
		r.permissiveLocalPart = enabled
		return r, nil
	}
}

func WithDKIMSignOptions(options *dkim.SignOptions) RedirectorOptionFunc {
	return func(r *Redirector) (*Redirector, error) {
		r.dkimSignOptions = options
		return r, nil
	}
}

func NewRedirectorFromYAML(b []byte, options ...RedirectorOptionFunc) (*Redirector, error) {
	var rr RedirectionRules
	err := yaml.Unmarshal(b, &rr)
	if err != nil {
		return nil, err
	}
	return NewRedirector(rr, options...)
}

func NewRedirectorFromYAMLFile(path string, options ...RedirectorOptionFunc) (*Redirector, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewRedirectorFromYAML(b, options...)
}

func NewRedirector(rr RedirectionRules, options ...RedirectorOptionFunc) (*Redirector, error) {
	r := &Redirector{
		Rules:  rr,
		logger: slog.New(logging.BlackholeHandler{}),
	}
	for _, option := range options {
		var err error
		r, err = option(r)
		if err != nil {
			return nil, err
		}
	}
	r.renderer = &address.AddressRenderer{
		Wrap:                folding,
		WrapLen:             998,
		PermissiveLocalPart: r.permissiveLocalPart,
	}
	r.parser = &address.AddressParser{
		PermissiveLocalPart: r.permissiveLocalPart,
	}
	r.logger.Info("redirector created", slog.Any("rules", len(rr)))
	for i, rule := range rr {
		r.logger.Info("rule", slog.Int("precedence", i), slog.String("match", rule.R.String()), slog.String("substitution", rule.S))
	}
	return r, nil
}

var folding = []byte{'\r', '\n', ' '}
var toB = []byte("to")
var dkimSignatureB = []byte("DKIM-Signature")

func formatReceptionDescriptor(rd *types.ReceptionDescriptor, recipient string) string {
	var sb strings.Builder
	sb.WriteString("Received: from ")
	sb.WriteString(rd.SenderHost)
	sb.WriteString("\r\n by ")
	sb.WriteString(rd.Host)
	sb.WriteString(" with ")
	sb.WriteString(rd.Protocol)
	sb.WriteString(" id ")
	sb.WriteString(rd.ID)
	sb.WriteString("\r\n for <")
	sb.WriteString(recipient)
	sb.WriteString(">; ")
	sb.WriteString(rd.Timestamp.Format(time.RFC1123Z))
	return sb.String()
}

func (rtr *Redirector) retouch(
	w io.Writer,
	m types.Mail,
	receptionDescriptor *types.ReceptionDescriptor,
	v func([]byte, []byte) ([]byte, error),
) error {
	var bw bytes.Buffer
	bl := &rfc5322.Builder{Writer: &bw}
	var s rfc5322.Store
	err := rfc5322.Scan(
		&bufio.BytesReaderWrapper{Reader: bytes.NewReader(m.Data())},
		rfc5322.ScannerHandlerFromFunctions(
			func(b []byte) error {
				err := s.HandleStraggler(b)
				if err != nil {
					return err
				}
				return bl.HandleStraggler(b)
			},
			func(chunks [][]byte) error {
				i := bytes.IndexByte(chunks[0], ':')
				if i < 0 {
					return nil
				}

				headerValueChunks := make([][]byte, len(chunks))
				headerValueChunks[0] = chunks[0][i+1:]
				copy(headerValueChunks[1:], chunks[1:])
				headerName := chunks[0][:i]

				// remove DKIM signature header
				if bytes.EqualFold(headerName, dkimSignatureB) {
					return nil
				}

				headerValue := bytes.Join(headerValueChunks, nil)
				headerValue, err := v(headerName, headerValue)
				if err != nil {
					return err
				}
				newChunks := bytes.Split(headerValue, folding[:2])
				newChunks[0] = append(
					append(
						append(make([]byte, 0, len(chunks[0])),
							chunks[0][0:i+1]...,
						),
						' ',
					),
					newChunks[0]...,
				)

				err = s.HandleHeaderLine(newChunks)
				if err != nil {
					return err
				}
				return bl.HandleHeaderLine(newChunks)
			},
			func(br bufio.BufferedReader) error {
				body, err := io.ReadAll(br)
				if err != nil {
					return err
				}
				err = bl.HandleBody(&bufio.BytesReaderWrapper{Reader: bytes.NewReader(body)})
				if err != nil {
					return err
				}
				if rtr.dkimSignOptions != nil {
					signer, err := dkim.NewSigner(rtr.dkimSignOptions)
					if err != nil {
						return err
					}
					_, err = signer.Write(bw.Bytes())
					if err != nil {
						return err
					}
					err = signer.Close()
					if err != nil {
						return err
					}
					dkimHeaderValue := signer.Signature()
					err = s.HandleHeaderLine([][]byte{[]byte(dkimHeaderValue[:len(dkimHeaderValue)-2])})
					if err != nil {
						return err
					}
				}
				{
					chunks := [][]byte{[]byte(formatReceptionDescriptor(receptionDescriptor, m.Recipient()))}
					err := s.HandleHeaderLine(chunks)
					if err != nil {
						return err
					}
				}
				return s.HandleBody(&bufio.BytesReaderWrapper{Reader: bytes.NewReader(body)})
			},
		))
	if err != nil {
		return err
	}
	{
		err = s.Replay(&rfc5322.Builder{Writer: w})
		if err != nil {
			return err
		}
	}
	return err
}

func (rtr *Redirector) rewriteAddresses(headerName, headerValue []byte, oldAddr, newAddr *address.Address) ([]byte, error) {
	addrs, err := rtr.parser.ParseListBytes(headerValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipients: %w", err)
	}

	newAddrs := make([]*address.Address, 0, len(addrs))
	rewrite := func(a *address.Address) *address.Address {
		if bytes.EqualFold(a.GetLocalPart(), oldAddr.GetLocalPart()) && bytes.EqualFold(a.GetDomain(), oldAddr.GetDomain()) {
			return &address.Address{
				Leadings:  a.Leadings,
				LocalPart: newAddr.LocalPart,
				Domain:    newAddr.Domain,
				Trailings: a.Trailings,
			}
		} else {
			return a
		}
	}
	for _, a := range addrs {
		if len(a.GroupList) != 0 {
			newGroupList := make([]*address.Address, 0, len(a.GroupList))
			for _, a := range a.GroupList {
				newGroupList = append(newGroupList, rewrite(a))
			}
			newAddrs = append(newAddrs, &address.Address{
				Leadings:  a.Leadings,
				GroupList: newGroupList,
				Trailings: a.Trailings,
			})
		} else {
			newAddrs = append(newAddrs, rewrite(a))
		}
	}

	offset := len(headerName) + 2
	b := make([]byte, offset, offset+len(headerValue))
	b = rtr.renderer.AppendList(b, newAddrs)
	return b[offset:], nil
}

func (rtr *Redirector) TryRedirect(m types.Mail, rd *types.ReceptionDescriptor) (bool, types.Mail, string, error) {
	logger := rtr.logger.With(slog.String("recipient", m.Recipient()))
	oldAddr, err := rtr.parser.Parse(m.Recipient())
	if err != nil {
		return false, m, "", fmt.Errorf("failed to parse recipient: %w", err)
	}
	for i, rule := range rtr.Rules {
		rtr.logger.Info("trying rule", slog.Int("precedence", i), slog.String("match", rule.R.String()), slog.String("substitution", rule.S))
		rcpt := RegexpSubstition(rule).Substitute(m.Recipient())
		if rcpt != m.Recipient() {
			logger := logger.With(slog.String("old_recipient", m.Recipient()), slog.String("new_recipient", rcpt))
			logger.Info("matched")
			newAddr, err := rtr.parser.Parse(rcpt)
			if err != nil {
				logger.Warn("failed to parse new recipient", slog.Any("error", err))
				break
			}
			body := m.Data()
			if body != nil {
				var b bytes.Buffer
				err = rtr.retouch(
					&b, m, rd,
					func(headerName, headerValue []byte) ([]byte, error) {
						var err error
						if bytes.EqualFold(headerName, toB) {
							headerValue, err = rtr.rewriteAddresses(headerName, headerValue, oldAddr, newAddr)
							if err != nil {
								return nil, fmt.Errorf("failed to rewrite addresses: %w", err)
							}
						}
						return headerValue, nil
					},
				)
				if err != nil {
					logger.Warn("failed to retouch", slog.Any("error", err))
					break
				}
				body = b.Bytes()
			}
			return true, types.NewMail(m.Sender(), rcpt, body), string(newAddr.GetDomain()), nil
		}
	}
	return false, m, "", err
}
