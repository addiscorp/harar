// The client against a stand-in harar on a unix socket: the requests it
// sends are the ones harar takes (the harar crate's PrimaryRequest, tag "op"),
// and every way harar can say no is an error naming why. The same cases as
// js/test and python/tests.
package harar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// standIn is a harar answering each request with reply(request).
type standIn struct {
	socket   string
	mu       sync.Mutex
	requests []map[string]any
}

func serve(t *testing.T, reply func(map[string]any) string) *standIn {
	t.Helper()
	// A short directory: a unix socket path is at most 104 bytes on macOS.
	dir, err := os.MkdirTemp("", "harar-go-")
	if err != nil {
		t.Fatal(err)
	}
	h := &standIn{socket: filepath.Join(dir, "h.sock")}
	l, err := net.Listen("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.RemoveAll(dir) })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			body, _ := io.ReadAll(conn)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			h.mu.Lock()
			h.requests = append(h.requests, req)
			h.mu.Unlock()
			_, _ = conn.Write([]byte(reply(req)))
			conn.Close()
		}
	}()
	return h
}

func (h *standIn) asked() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests
}

func answer(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func stripe(r map[string]any) string {
	if r["op"] == "hosts" {
		return answer(map[string]any{"ok": true, "hosts": []string{"api.stripe.com", "*.stripe.com"}})
	}
	if r["op"] == "send" && r["host"] == "api.stripe.com" {
		return answer(map[string]any{"ok": true, "value": "sk_live_real"})
	}
	return answer(map[string]any{"ok": false, "error": "not_allowed"})
}

// fails checks err is a harar Error whose message matches why.
func fails(t *testing.T, err error, why string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want a harar error matching %q, got %v", why, err)
	}
	if !regexp.MustCompile(why).MatchString(e.Error()) {
		t.Fatalf("want an error matching %q, got %q", why, e.Error())
	}
}

func TestHostsAndSendAskHararExactlyAndASendIsForOneHost(t *testing.T) {
	ctx := context.Background()
	h := serve(t, stripe)
	v := VaultAt(h.socket)
	hosts, err := v.Hosts(ctx, "prod/shop/STRIPE_KEY")
	if err != nil || !reflect.DeepEqual(hosts, []string{"api.stripe.com", "*.stripe.com"}) {
		t.Fatalf("hosts: %v %v", hosts, err)
	}
	value, err := v.Send(ctx, "prod/shop/STRIPE_KEY", "api.stripe.com")
	if err != nil || value != "sk_live_real" {
		t.Fatalf("send: %q %v", value, err)
	}
	_, err = v.Send(ctx, "prod/shop/STRIPE_KEY", "evil.example.com")
	fails(t, err, `^harar refused prod/shop/STRIPE_KEY to evil\.example\.com: not_allowed$`)
	want := []map[string]any{
		{"op": "hosts", "key": "prod/shop/STRIPE_KEY"},
		{"op": "send", "key": "prod/shop/STRIPE_KEY", "host": "api.stripe.com"},
		{"op": "send", "key": "prod/shop/STRIPE_KEY", "host": "evil.example.com"},
	}
	if got := h.asked(); !reflect.DeepEqual(got, want) {
		t.Fatalf("harar was asked %v, want %v", got, want)
	}
}

func TestEveryWayHararCanFailIsAnErrorNamingWhy(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ answer, why string }{
		{"not json", `did not answer with JSON`},
		{"null", `did not answer with an object`},
		{"[1]", `did not answer with an object`},
		{`{"ok":true}`, `no value|no hosts`},
		{`{"ok":true,"hosts":["a",1]}`, `no value|no hosts`},
		{`{"ok":"true","value":"x"}`, `harar refused .*: no answer`},
		{`{"ok":false,"error":"locked"}`, `harar refused .*: locked`},
		{strings.Repeat("x", MaxAnswer+1), `too long an answer`},
	} {
		h := serve(t, func(map[string]any) string { return c.answer })
		v := VaultAt(h.socket)
		_, err := v.Send(ctx, "a/b", "x.example.com")
		fails(t, err, c.why)
		_, err = v.Hosts(ctx, "a/b")
		fails(t, err, c.why)
	}
	_, err := VaultAt("/nonexistent/h.sock").Hosts(ctx, "a/b")
	fails(t, err, `^harar at /nonexistent/h\.sock: `)
	_, err = VaultAt("relative.sock").Hosts(ctx, "a/b")
	fails(t, err, `absolute path`)
}

// silent is a harar that takes connections and never answers.
func silent(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "harar-go-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "h.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn) // read nothing, answer nothing
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
		os.RemoveAll(dir)
	})
	return socket
}

func TestAHararThatDoesNotAnswerEndsAtTheDeadlineOrACancel(t *testing.T) {
	socket := silent(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := VaultAt(socket).Secrets.Resolve(ctx, "harar://a/b")
	fails(t, err, `did not answer in time`)
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("waited %s past a 200ms deadline", waited)
	}

	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start = time.Now()
	_, err = VaultAt(socket).Hosts(ctx, "a/b")
	fails(t, err, `: cancelled$`)
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("waited %s past a cancel at 200ms", waited)
	}
}

func TestSecretsResolveReadsTheKeyAHararReferenceNames(t *testing.T) {
	ctx := context.Background()
	values := map[string]string{"prod/shop/STRIPE_KEY": "sk_live_real", "prod/shop/OTHER": "other"}
	h := serve(t, func(r map[string]any) string {
		if value, ok := values[r["key"].(string)]; ok {
			return answer(map[string]any{"ok": true, "value": value})
		}
		return answer(map[string]any{"ok": false, "error": "not_found"})
	})
	v := VaultAt(h.socket)
	key, err := v.Secrets.Resolve(ctx, "harar://prod/shop/STRIPE_KEY")
	if err != nil || key != "sk_live_real" {
		t.Fatalf("resolve: %q %v", key, err)
	}
	all, err := v.Secrets.ResolveAll(ctx, []string{"harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"})
	if err != nil || !reflect.DeepEqual(all, []string{"sk_live_real", "other"}) {
		t.Fatalf("resolve all: %v %v", all, err)
	}
	_, err = v.Secrets.Resolve(ctx, "harar://prod/shop/GONE")
	fails(t, err, `^harar refused harar://prod/shop/GONE: not_found$`)
	// Not a reference: refused before harar is asked anything.
	for _, notOne := range []string{"prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", ""} {
		_, err := v.Secrets.Resolve(ctx, notOne)
		fails(t, err, `not a harar:// reference`)
	}
	want := []map[string]any{
		{"op": "get", "key": "prod/shop/STRIPE_KEY"},
		{"op": "get", "key": "prod/shop/STRIPE_KEY"},
		{"op": "get", "key": "prod/shop/OTHER"},
		{"op": "get", "key": "prod/shop/GONE"},
	}
	if got := h.asked(); !reflect.DeepEqual(got, want) {
		t.Fatalf("harar was asked %v, want %v", got, want)
	}
}

func TestVaultAsksTheAgentWhereHararAgentListens(t *testing.T) {
	t.Setenv("HOME", "/home/someone")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	want := "/run/user/1000/harar/agent.sock"
	if runtime.GOOS == "darwin" {
		want = "/home/someone/Library/Application Support/harar/agent.sock"
	}
	if got := AgentSocket(); got != want {
		t.Fatalf("agent socket %q, want %q", got, want)
	}
	_, err := Vault().Secrets.Resolve(context.Background(), "harar://a/b")
	fails(t, err, "^harar at "+regexp.QuoteMeta(want)+": ")
	t.Setenv("XDG_RUNTIME_DIR", "")
	if runtime.GOOS != "darwin" {
		if got := AgentSocket(); got != "/home/someone/.harar/agent.sock" {
			t.Fatalf("agent socket %q with no XDG_RUNTIME_DIR", got)
		}
	}
}
