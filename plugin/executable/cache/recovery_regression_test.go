package cache

import (
 "bytes"
 "context"
 "net"
 "testing"
 "time"

 "github.com/IrineSistiana/mosdns/v5/pkg/query_context"
 "github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
 "github.com/miekg/dns"
)

func TestDumpRestorePreservesOriginalTTL(t *testing.T) {
 src := NewCache(&Args{}, Opts{})
 defer src.Close()
 q := new(dns.Msg).SetQuestion("restore.example.", dns.TypeA)
 r := new(dns.Msg).SetReply(q)
 r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "restore.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
 if !saveRespToCache(getMsgKey(q), r, src.backend, 0) { t.Fatal("cannot cache response") }
 var b bytes.Buffer
 if _, err := src.writeDump(&b); err != nil { t.Fatal(err) }
 dst := NewCache(&Args{}, Opts{})
 defer dst.Close()
 if _, err := dst.readDump(&b); err != nil { t.Fatal(err) }
 got, lazy := getRespFromCache(getMsgKey(q), dst.backend, false, 5)
 if lazy || got == nil || len(got.Answer) != 1 || got.Answer[0].Header().Ttl < 55 {
  t.Fatalf("restored response must retain its TTL: %+v, lazy=%v", got, lazy)
 }
}

func TestLazyRefreshCannotRestoreFlushedEntry(t *testing.T) {
 c := NewCache(&Args{LazyCacheTTL: 60}, Opts{})
 defer c.Close()
 q := new(dns.Msg).SetQuestion("lazy-flush.example.", dns.TypeA)
 r := cacheTestResponse(q)
 saveRespToCache(getMsgKey(q), r, c.backend, 60)
 k := key(getMsgKey(q))
 started := make(chan struct{})
 release := make(chan struct{})
 executor := sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
  close(started)
  <-release
  qc.SetResponse(cacheTestResponse(qc.Q()))
  return nil
 })
 chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: executor}}, nil)
 c.doLazyUpdate(getMsgKey(q), query_context.NewContext(q.Copy()), chain)
 select { case <-started: case <-time.After(time.Second): t.Fatal("refresh did not start") }
 c.Flush()
 close(release)
 c.lazyWG.Wait()
 if _, _, exists := c.backend.Get(k); exists { t.Fatal("lazy refresh restored a flushed entry") }
}
