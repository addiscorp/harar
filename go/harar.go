// Package harar is harar's client for Go:
//
//	import harar "github.com/addiscorp/harar/go"
//
//	vault := harar.Vault()                                                    // the agent on this machine
//	key, err := vault.Secrets.Resolve(ctx, "harar://prod/shop/STRIPE_KEY") // the key it names
//
// A gateway that attaches keys on their way out asks where each may go, and
// for it for one host only: [Client.Hosts] and [Client.Send].
//
// One JSON request on harar's local socket, the write side closed, one JSON
// answer: the protocol the per-user agent and a primary both speak. harar
// decides every send; this client holds nothing.
package harar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// ReferencePrefix is what a reference to a vault key starts with, as op://
// for 1Password.
const ReferencePrefix = "harar://"

// MaxAnswer is the longest answer harar may send; anything longer is refused.
const MaxAnswer = 1 << 20

// Timeout is how long harar has to answer (a per-user agent may be asking for
// Touch ID). A context with an earlier deadline ends the wait sooner.
const Timeout = 60 * time.Second

// Error is harar refusing, or a harar that could not be asked; the message
// names why.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func fail(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Reference returns the vault key value names, if the whole value is a
// harar:// reference.
func Reference(value string) (string, bool) {
	key, ok := strings.CutPrefix(value, ReferencePrefix)
	if !ok || key == "" || strings.IndexFunc(key, unicode.IsSpace) >= 0 {
		return "", false
	}
	return key, true
}

// AgentSocket is where the per-user agent (`harar agent`) listens: the harar
// binary's rule.
func AgentSocket() string {
	home, runtimeDir := os.Getenv("HOME"), os.Getenv("XDG_RUNTIME_DIR")
	if runtime.GOOS == "darwin" && home != "" {
		return filepath.Join(home, "Library/Application Support/harar", "agent.sock")
	}
	if runtimeDir != "" {
		return filepath.Join(runtimeDir, "harar", "agent.sock")
	}
	if home == "" {
		home = "/"
	}
	return filepath.Join(home, ".harar", "agent.sock")
}

// Client is a vault on harar's socket: the secrets its references name, and
// for a gateway, where each may go and the secret itself for one host only.
type Client struct {
	// Secrets resolves harar:// references, the shape of 1Password's
	// client.Secrets.Resolve(ctx, "op://...").
	Secrets *Secrets
	socket  string
}

// Vault is the per-user agent on this machine (`harar agent`).
func Vault() *Client { return VaultAt(AgentSocket()) }

// VaultAt is harar at socket, an absolute path: a primary is /run/harar.sock.
func VaultAt(socket string) *Client {
	c := &Client{socket: socket}
	c.Secrets = &Secrets{client: c}
	return c
}

// Secrets resolves harar:// references to their values. A value is read when
// asked for and held only by you.
type Secrets struct{ client *Client }

// Resolve returns the value ref (harar://prod/shop/STRIPE_KEY) names.
func (s *Secrets) Resolve(ctx context.Context, ref string) (string, error) {
	key, ok := Reference(ref)
	if !ok {
		return "", fail("not a harar:// reference: %q", ref)
	}
	answer, err := s.client.ask(ctx, request{Op: "get", Key: key}, ref)
	if err != nil {
		return "", err
	}
	value, ok := answer["value"].(string)
	if !ok {
		return "", fail("harar sent no value for %s", ref)
	}
	return value, nil
}

// ResolveAll returns each reference's value, in order; the first that fails
// is the error.
func (s *Secrets) ResolveAll(ctx context.Context, refs []string) ([]string, error) {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		value, err := s.Resolve(ctx, ref)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

// Hosts returns, for a gateway, the host patterns secret may go to: an exact
// name, or *.example.com for any name under it (never the name itself).
func (c *Client) Hosts(ctx context.Context, secret string) ([]string, error) {
	answer, err := c.ask(ctx, request{Op: "hosts", Key: secret}, secret)
	if err != nil {
		return nil, err
	}
	list, ok := answer["hosts"].([]any)
	if !ok {
		return nil, fail("harar sent no hosts for %s", secret)
	}
	hosts := make([]string, 0, len(list))
	for _, h := range list {
		host, ok := h.(string)
		if !ok {
			return nil, fail("harar sent no hosts for %s", secret)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

// Send returns, for a gateway, secret's value for a request to host only.
func (c *Client) Send(ctx context.Context, secret, host string) (string, error) {
	answer, err := c.ask(ctx, request{Op: "send", Key: secret, Host: host}, secret+" to "+host)
	if err != nil {
		return "", err
	}
	value, ok := answer["value"].(string)
	if !ok {
		return "", fail("harar refused %s to %s: no value", secret, host)
	}
	return value, nil
}

// request is what harar takes: {"op":"get","key":...}, {"op":"hosts","key":...}
// or {"op":"send","key":...,"host":...}.
type request struct {
	Op   string `json:"op"`
	Key  string `json:"key"`
	Host string `json:"host,omitempty"`
}

// ask sends one request to harar, and returns its answer if it says ok;
// otherwise why not.
func (c *Client) ask(ctx context.Context, req request, what string) (map[string]any, error) {
	if !filepath.IsAbs(c.socket) {
		return nil, fail("harar.VaultAt(%q): the socket is an absolute path", c.socket)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, c.unreachable(ctx, err)
	}
	defer conn.Close()
	// The deadline holds the reads and writes to it; a cancel ends them now.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fail("harar request for %s: %v", what, err)
	}
	if _, err := conn.Write(body); err != nil {
		return nil, c.unreachable(ctx, err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		return nil, c.unreachable(ctx, err)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, MaxAnswer+1))
	if err != nil {
		return nil, c.unreachable(ctx, err)
	}
	if len(raw) > MaxAnswer {
		return nil, fail("harar sent too long an answer")
	}

	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fail("harar at %s did not answer with JSON", c.socket)
	}
	answer, ok := parsed.(map[string]any)
	if !ok {
		return nil, fail("harar at %s did not answer with an object", c.socket)
	}
	if answer["ok"] == true {
		return answer, nil
	}
	why, ok := answer["error"].(string)
	if !ok {
		why = "no answer"
	}
	return nil, fail("harar refused %s: %s", what, why)
}

// unreachable names why harar could not be asked: the wait ran out, the
// caller cancelled, or the socket said no.
func (c *Client) unreachable(ctx context.Context, err error) error {
	// A cancel ends the wait by moving the deadline, so it is checked first.
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fail("harar at %s: cancelled", c.socket)
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return fail("harar did not answer in time (%s at most)", Timeout)
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	return fail("harar at %s: %v", c.socket, err)
}

// Resolver resolves harar:// references: [Client.Secrets] on harar's local
// socket and [EdgeVault.Secrets] at a harar edge both are one, so code that
// only resolves takes either.
type Resolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
	ResolveAll(ctx context.Context, refs []string) ([]string, error)
}

var (
	_ Resolver = (*Secrets)(nil)
	_ Resolver = (*EdgeSecrets)(nil)
)

// edgeToken is a harar edge service token, as `harar edge token create` makes it.
var edgeToken = regexp.MustCompile(`\Aharar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\z`)

// edgeURL is https://, or http:// to this machine only.
var edgeURL = regexp.MustCompile(`\A(https://[^/]|http://(127\.0\.0\.1|localhost|\[::1\])([:/]|\z))`)

// EdgeVault is a vault at a harar edge (docs/edge.md): it resolves
// references, and only those its service token may read. Hosts and Send are
// for gateways on harar's local socket.
type EdgeVault struct {
	Secrets *EdgeSecrets
}

// Edge is a harar edge, for a service off your network: its URL
// (https://harar-edge.<you>.workers.dev) and a service token from
// `harar edge token create`, read from the platform's secrets.
func Edge(url, token string) (*EdgeVault, error) {
	if !edgeURL.MatchString(url) {
		return nil, fail("harar.Edge: the edge is an https:// URL")
	}
	if !edgeToken.MatchString(token) {
		return nil, fail("harar.Edge: the token is a harar edge service token (harar edge token create)")
	}
	return &EdgeVault{Secrets: &EdgeSecrets{edge: strings.TrimRight(url, "/"), token: token}}, nil
}

// EdgeSecrets resolves harar:// references at a harar edge, with a service token.
type EdgeSecrets struct {
	edge, token string
}

// Resolve returns the value ref names.
func (s *EdgeSecrets) Resolve(ctx context.Context, ref string) (string, error) {
	values, err := s.ResolveAll(ctx, []string{ref})
	if err != nil {
		return "", err
	}
	return values[0], nil
}

// ResolveAll returns each reference's value, in order, from one request:
// all or nothing.
func (s *EdgeSecrets) ResolveAll(ctx context.Context, refs []string) ([]string, error) {
	if len(refs) == 0 {
		return []string{}, nil
	}
	for _, ref := range refs {
		if _, ok := Reference(ref); !ok {
			return nil, fail("not a harar:// reference: %q", ref)
		}
	}
	what := refs[0]
	if len(refs) > 1 {
		what = fmt.Sprintf("%d references", len(refs))
	}
	status, body, err := s.post(ctx, refs)
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fail("harar at %s did not answer with JSON (%d)", s.edge, status)
	}
	answer, ok := parsed.(map[string]any)
	if !ok {
		return nil, fail("harar at %s did not answer with an object", s.edge)
	}
	if status < 200 || status > 299 {
		code, ok := answer["error"].(string)
		if !ok {
			code = fmt.Sprint(status)
		}
		if message, ok := answer["message"].(string); ok {
			code += ": " + message
		}
		return nil, fail("harar refused %s: %s", what, code)
	}
	list, ok := answer["values"].([]any)
	if !ok || len(list) != len(refs) {
		return nil, fail("harar sent no value for %s", what)
	}
	values := make([]string, len(list))
	for i, v := range list {
		if values[i], ok = v.(string); !ok {
			return nil, fail("harar sent no value for %s", what)
		}
	}
	return values, nil
}

// post sends one POST of /v1/resolve, and returns the status and the body,
// refused past MaxAnswer bytes.
func (s *EdgeSecrets) post(ctx context.Context, refs []string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	body, err := json.Marshal(map[string][]string{"refs": refs})
	if err != nil {
		return 0, nil, fail("harar request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.edge+"/v1/resolve", bytes.NewReader(body))
	if err != nil {
		return 0, nil, fail("harar at %s: %v", s.edge, err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+s.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, s.unreachable(ctx, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxAnswer+1))
	if err != nil {
		return 0, nil, s.unreachable(ctx, err)
	}
	if len(raw) > MaxAnswer {
		return 0, nil, fail("harar sent too long an answer")
	}
	return res.StatusCode, raw, nil
}

// unreachable names why the edge could not be asked, without the URL's
// own error text, which repeats the request.
func (s *EdgeSecrets) unreachable(ctx context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fail("harar at %s: cancelled", s.edge)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fail("harar at %s: did not answer in time (%s at most)", s.edge, Timeout)
	}
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fail("harar at %s: %v", s.edge, err)
}
