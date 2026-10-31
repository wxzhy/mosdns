package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
)

func cacheSafetyQuery(class uint16) *query_context.Context {
	q := new(dns.Msg).SetQuestion("safety.example.", dns.TypeA)
	q.Question[0].Qclass = class
	return query_context.NewContext(q)
}

func TestCacheKeyIsolatesClassAndEDNS(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	queries := 0
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() != nil {
			return nil
		}
		queries++
		r := new(dns.Msg).SetReply(q.Q())
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: q.QQuestion().Qclass, Ttl: 60}, A: net.IPv4(192, 0, 2, 41)}}
		q.SetResponse(r)
		return nil
	})}}, nil)
	for _, class := range []uint16{dns.ClassINET, dns.ClassCHAOS, dns.ClassINET} {
		q := cacheSafetyQuery(class)
		if err := c.Exec(context.Background(), q, chain); err != nil {
			t.Fatal(err)
		}
		if q.R().Answer[0].Header().Class != class {
			t.Fatalf("wrong class returned for %d", class)
		}
	}
	if queries != 2 {
		t.Fatalf("cache should partition classes: calls=%d", queries)
	}
	for _, ip := range []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)} {
		q := cacheSafetyQuery(dns.ClassINET)
		q.Q().SetEdns0(1232, false)
		q.Q().IsEdns0().Option = append(q.Q().IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: ip})
		if getMsgKey(q.Q()) != "" {
			t.Fatal("ECS request must not use shared cache")
		}
		if err := c.Exec(context.Background(), q, chain); err != nil {
			t.Fatal(err)
		}
	}
	if queries != 4 {
		t.Fatalf("ECS requests were served by shared cache: calls=%d", queries)
	}
}

func TestCacheDoesNotStoreFailedOrMutatedQueries(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	calls := 0
	failed := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		calls++
		q.SetResponse(cacheTestResponse(q.Q()))
		return errors.New("upstream failed")
	})}}, nil)
	for i := 0; i < 2; i++ {
		q := cacheSafetyQuery(dns.ClassINET)
		if err := c.Exec(context.Background(), q, failed); err == nil {
			t.Fatal("expected error")
		}
	}
	if calls != 2 {
		t.Fatal("partial response from failed execution was cached")
	}
	changed := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		q.Q().SetEdns0(1232, false)
		q.Q().IsEdns0().Option = append(q.Q().IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 1)})
		q.SetResponse(cacheTestResponse(q.Q()))
		return nil
	})}}, nil)
	q := cacheSafetyQuery(dns.ClassINET)
	if err := c.Exec(context.Background(), q, changed); err != nil {
		t.Fatal(err)
	}
	if _, _, exists := c.backend.Get(key(getMsgKey(cacheSafetyQuery(dns.ClassINET).Q()))); exists {
		t.Fatal("downstream-injected ECS response was cached under a generic key")
	}
}

func TestInvalidCacheDumpDoesNotPartiallyImport(t *testing.T) {
	src := NewCache(&Args{}, Opts{})
	defer src.Close()
	q := cacheSafetyQuery(dns.ClassINET)
	if !saveRespToCache(getMsgKey(q.Q()), cacheTestResponse(q.Q()), src.backend, 0) {
		t.Fatal("failed to populate source cache")
	}
	var dump bytes.Buffer
	if _, err := src.writeDump(&dump); err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(dump.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var payload bytes.Buffer
	if _, err := payload.ReadFrom(gr); err != nil {
		t.Fatal(err)
	}
	name := gr.Name
	_ = gr.Close()
	var damaged bytes.Buffer
	gw := gzip.NewWriter(&damaged)
	gw.Name = name
	// Valid first block followed by a complete length header and truncated body.
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], 10)
	_, _ = gw.Write(payload.Bytes())
	_, _ = gw.Write(header[:])
	_, _ = gw.Write([]byte{1, 2})
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	dst := NewCache(&Args{}, Opts{})
	defer dst.Close()
	w := httptest.NewRecorder()
	dst.Api().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/load_dump", bytes.NewReader(damaged.Bytes())))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected rejected dump, got %d", w.Code)
	}
	if _, _, ok := dst.backend.Get(key(getMsgKey(q.Q()))); ok {
		t.Fatal("rejected dump partially modified live cache")
	}
}

func TestLegacyCacheDumpKeyIsMigratedWithQCLASS(t *testing.T) {
	src := NewCache(&Args{}, Opts{})
	defer src.Close()
	q := cacheSafetyQuery(dns.ClassCHAOS)
	name := q.QQuestion().Name
	oldKey := append([]byte{0, 0, byte(dns.TypeA), byte(len(name))}, name...)
	r := new(dns.Msg).SetReply(q.Q())
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassCHAOS, Ttl: 60}, A: net.IPv4(192, 0, 2, 10)}}
	if !saveRespToCache(string(oldKey), r, src.backend, 0) {
		t.Fatal("could not store legacy entry")
	}
	var dump bytes.Buffer
	if _, err := src.writeDump(&dump); err != nil {
		t.Fatal(err)
	}
	dst := NewCache(&Args{}, Opts{})
	defer dst.Close()
	if _, err := dst.readDump(&dump); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := dst.backend.Get(key(getMsgKey(q.Q()))); !ok {
		t.Fatal("legacy dump entry was not migrated to QCLASS-aware key")
	}
	if _, _, ok := dst.backend.Get(key(getMsgKey(cacheSafetyQuery(dns.ClassINET).Q()))); ok {
		t.Fatal("migrated CHAOS entry leaked into IN query cache")
	}
}

func TestCacheFlushRequiresPOST(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	q := cacheSafetyQuery(dns.ClassINET)
	key := key(getMsgKey(q.Q()))
	if !saveRespToCache(string(key), cacheTestResponse(q.Q()), c.backend, 0) {
		t.Fatal("failed to seed cache")
	}
	get := httptest.NewRecorder()
	c.Api().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/flush", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /flush status=%d, want 405", get.Code)
	}
	if _, _, ok := c.backend.Get(key); !ok {
		t.Fatal("GET /flush cleared the cache")
	}
	post := httptest.NewRecorder()
	c.Api().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/flush", nil))
	if post.Code != http.StatusOK {
		t.Fatalf("POST /flush status=%d, want 200", post.Code)
	}
	if _, _, ok := c.backend.Get(key); ok {
		t.Fatal("POST /flush did not clear the cache")
	}
}
