package hosts

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func hostsAnswer(h *Hosts) string {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	c := query_context.NewContext(q)
	_ = h.Exec(context.Background(), c)
	if r := c.R(); r != nil && len(r.Answer) > 0 {
		if a, ok := r.Answer[0].(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func awaitHosts(t *testing.T, h *Hosts, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hostsAnswer(h) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hosts returned %q; expected %q after reload", hostsAnswer(h), want)
}

func TestHostsHotReloadRollbackAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("example.test 192.0.2.1\n")
	h, err := newHosts(nil, &Args{Files: []string{path}}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	awaitHosts(t, h, "192.0.2.1")

	// Invalid replacement must never discard the previous good matcher.
	write("example.test not-an-ip\n")
	time.Sleep(80 * time.Millisecond)
	if got := hostsAnswer(h); got != "192.0.2.1" {
		t.Fatalf("invalid reload replaced good rules: %q", got)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = hostsAnswer(h)
			}
		}()
	}
	write("example.test 192.0.2.99\n")
	awaitHosts(t, h, "192.0.2.99")
	wg.Wait()

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	write("example.test 192.0.2.8\n")
	time.Sleep(40 * time.Millisecond)
	if got := hostsAnswer(h); got != "192.0.2.99" {
		t.Fatalf("rules changed after Close: %q", got)
	}
}
