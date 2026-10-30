package arbitrary

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

func arbitraryAnswer(a *Arbitrary) string {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	c := query_context.NewContext(q)
	_ = a.Exec(context.Background(), c)
	if r := c.R(); r != nil && len(r.Answer) > 0 {
		if addr, ok := r.Answer[0].(*dns.A); ok {
			return addr.A.String()
		}
	}
	return ""
}

func awaitArbitrary(t *testing.T, a *Arbitrary, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if arbitraryAnswer(a) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("arbitrary returned %q; expected %q", arbitraryAnswer(a), want)
}

func TestArbitraryHotReloadRollbackAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.zone")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("example.test. 60 IN A 192.0.2.1\n")
	a, err := newArbitrary(nil, &Args{Files: []string{path}}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	awaitArbitrary(t, a, "192.0.2.1")

	write("example.test. 60 IN A invalid-ip\n")
	time.Sleep(80 * time.Millisecond)
	if got := arbitraryAnswer(a); got != "192.0.2.1" {
		t.Fatalf("invalid reload replaced good zone: %q", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = arbitraryAnswer(a)
			}
		}()
	}
	write("example.test. 60 IN A 192.0.2.99\n")
	awaitArbitrary(t, a, "192.0.2.99")
	wg.Wait()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	write("example.test. 60 IN A 192.0.2.8\n")
	time.Sleep(40 * time.Millisecond)
	if got := arbitraryAnswer(a); got != "192.0.2.99" {
		t.Fatalf("zone changed after Close: %q", got)
	}
}
