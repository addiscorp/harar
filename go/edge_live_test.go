package harar

import (
	"context"
	"os"
	"testing"
)

// TestLiveEdge runs against a real harar edge when edge/test/clients-e2e.sh
// names one (HARAR_TEST_EDGE_URL, HARAR_TEST_EDGE_TOKEN: test tooling only),
// and is skipped otherwise.
func TestLiveEdge(t *testing.T) {
	url, token := os.Getenv("HARAR_TEST_EDGE_URL"), os.Getenv("HARAR_TEST_EDGE_TOKEN")
	if url == "" {
		t.Skip("no live edge (edge/test/clients-e2e.sh sets one)")
	}
	v, err := Edge(url, token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, err := v.Secrets.Resolve(ctx, "harar://prod/shop/STRIPE_KEY")
	if err != nil || key != "sk_live_e2e" {
		t.Fatalf("resolve: %q %v", key, err)
	}
	_, err = v.Secrets.Resolve(ctx, "harar://prod/site/DATABASE_URL")
	fails(t, err, `^harar refused harar://prod/site/DATABASE_URL: not_allowed`)
}
