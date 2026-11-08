// The client against a stand-in harar edge over HTTP: what it sends is the
// edge's POST /v1/resolve (docs/edge.md §5) with the service token, and every
// way the edge can say no is an error naming why. The same cases as
// js/test/edge.test.js.
package harar

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const testToken = "harar_edge_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type edgeRequest struct {
	Method, URL, Auth, Type string
	Body                    map[string]any
}

// standInEdge is an edge mounted under /functions/v1/harar-edge, as on Supabase.
func standInEdge(t *testing.T, reply func(refs []string) (int, string)) (string, func() []edgeRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []edgeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		requests = append(requests, edgeRequest{r.Method, r.URL.Path, r.Header.Get("authorization"), r.Header.Get("content-type"), body})
		mu.Unlock()
		var refs []string
		for _, r := range body["refs"].([]any) {
			refs = append(refs, r.(string))
		}
		status, text := reply(refs)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/functions/v1/harar-edge/", func() []edgeRequest {
		mu.Lock()
		defer mu.Unlock()
		return requests
	}
}

func stripeEdge(refs []string) (int, string) {
	values := map[string]string{"harar://prod/shop/STRIPE_KEY": "sk_live_real", "harar://prod/shop/OTHER": "other"}
	out := []string{}
	for _, r := range refs {
		v, ok := values[r]
		if !ok {
			return 403, `{"error":"not_allowed","message":"this caller may not read prod/site/DATABASE_URL"}`
		}
		out = append(out, v)
	}
	b, _ := json.Marshal(map[string][]string{"values": out})
	return 200, string(b)
}

func TestAnEdgeVaultResolvesWithOnePostOfV1ResolveTheServiceTokenAsItsBearer(t *testing.T) {
	ctx := context.Background()
	url, asked := standInEdge(t, stripeEdge)
	v, err := Edge(url, testToken)
	if err != nil {
		t.Fatal(err)
	}
	var r Resolver = v.Secrets // the same interface as the socket vault's
	key, err := r.Resolve(ctx, "harar://prod/shop/STRIPE_KEY")
	if err != nil || key != "sk_live_real" {
		t.Fatalf("resolve: %q %v", key, err)
	}
	all, err := r.ResolveAll(ctx, []string{"harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"})
	if err != nil || !reflect.DeepEqual(all, []string{"sk_live_real", "other"}) {
		t.Fatalf("resolve all: %v %v", all, err)
	}
	if none, err := r.ResolveAll(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("resolve none: %v %v", none, err)
	}
	_, err = r.Resolve(ctx, "harar://prod/site/DATABASE_URL")
	fails(t, err, `^harar refused harar://prod/site/DATABASE_URL: not_allowed: this caller may not read`)
	for _, notOne := range []string{"prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", ""} {
		_, err := r.Resolve(ctx, notOne)
		fails(t, err, `not a harar:// reference`)
	}
	_, err = r.ResolveAll(ctx, []string{"harar://prod/shop/OTHER", "nope"})
	fails(t, err, `not a harar:// reference: "nope"`)
	want := func(refs ...string) edgeRequest {
		list := make([]any, len(refs))
		for i, r := range refs {
			list[i] = r
		}
		return edgeRequest{"POST", "/functions/v1/harar-edge/v1/resolve", "Bearer " + testToken, "application/json", map[string]any{"refs": list}}
	}
	expected := []edgeRequest{
		want("harar://prod/shop/STRIPE_KEY"),
		want("harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"),
		want("harar://prod/site/DATABASE_URL"),
	}
	if got := asked(); !reflect.DeepEqual(got, expected) {
		t.Fatalf("the edge was asked %+v, want %+v", got, expected)
	}
}

func TestEveryWayAnEdgeCanFailIsAnErrorNamingWhyAndTheTokenIsNeverInIt(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		status    int
		text, why string
	}{
		{200, "not json", `did not answer with JSON \(200\)`},
		{502, "<html>bad gateway</html>", `did not answer with JSON \(502\)`},
		{200, "[1]", `did not answer with an object`},
		{200, `{"values":[]}`, `no value for`},
		{200, `{"values":[7]}`, `no value for`},
		{401, `{"error":"revoked","message":"this token was revoked"}`, `harar refused .*: revoked: this token was revoked`},
		{500, `{}`, `harar refused .*: 500`},
		{200, strings.Repeat("x", MaxAnswer+1), `too long an answer`},
	} {
		url, _ := standInEdge(t, func([]string) (int, string) { return c.status, c.text })
		v, err := Edge(url, testToken)
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Secrets.Resolve(ctx, "harar://a/b")
		fails(t, err, c.why)
		if strings.Contains(err.Error(), testToken[28:]) {
			t.Fatalf("the token is in %q", err)
		}
	}
	v, _ := Edge("http://127.0.0.1:1", testToken)
	_, err := v.Secrets.Resolve(ctx, "harar://a/b")
	fails(t, err, `^harar at http://127.0.0.1:1: `)
	if strings.Contains(err.Error(), testToken[28:]) {
		t.Fatalf("the token is in %q", err)
	}
}

func TestAnEdgeIsHTTPSAndItsTokenAHararEdgeToken(t *testing.T) {
	for _, c := range []struct{ url, token, why string }{
		{"http://edge.example", testToken, `the edge is an https:// URL`},
		{"http://localhost.evil.example", testToken, `the edge is an https:// URL`},
		{"https://edge.example", "", `service token`},
		{"https://edge.example", "sk_live_oops", `service token`},
	} {
		_, err := Edge(c.url, c.token)
		fails(t, err, c.why)
		if c.token != "" && strings.Contains(err.Error(), c.token) {
			t.Fatalf("the token is in %q", err)
		}
	}
	for _, ok := range []string{"https://harar-edge.you.workers.dev", "http://localhost:8787", "http://127.0.0.1"} {
		if _, err := Edge(ok, testToken); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}
