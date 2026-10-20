package speedtest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func TestTCPProbeClosesSuccessfulConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		_, err = conn.Read(b[:])
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			closed <- err
			return
		}
		closed <- nil
	}()
	m := NewManager(Options{})
	defer m.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	r := m.Measure(context.Background(), netip.MustParseAddr("127.0.0.1"), Config{TCPPorts: []uint16{port}, Timeout: time.Second})
	if r.Outcome != Success || r.RTT < 0 {
		t.Fatalf("TCP result: %#v", r)
	}
	if err := <-closed; err != nil {
		t.Fatalf("successful socket not closed: %v", err)
	}
	if r := m.Measure(context.Background(), netip.MustParseAddr("127.0.0.1"), config(port)); r.Outcome != Success {
		t.Fatalf("second config: %#v", r)
	}
}

func TestProBingSingleEchoSetupAndPeer(t *testing.T) {
	for _, tc := range []struct {
		ip, network string
		privileged  bool
	}{
		{"192.0.2.1", "udp4", false},
		{"192.0.2.1", "ip4:icmp", true},
		{"2001:db8::1", "udp6", false},
		{"fe80::1%test-zone", "ip6:ipv6-icmp", true},
	} {
		t.Run(tc.network+tc.ip, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.ip)
			p := newICMPPinger(ip, tc.network)
			defer p.Stop()
			if p.Count != 1 || p.RecordRtts || p.RecordTTLs || p.Privileged() != tc.privileged {
				t.Fatalf("incorrect one-shot pro-bing settings: %+v", p)
			}
			if p.IPAddr().String() != ip.String() {
				t.Fatalf("target changed: got %s, want %s", p.IPAddr(), ip)
			}
		})
	}
	if !sameICMPPeer(&net.IPAddr{IP: net.ParseIP("192.0.2.1")}, testIP) || sameICMPPeer(&net.IPAddr{IP: net.ParseIP("192.0.2.2")}, testIP) || sameICMPPeer(nil, testIP) {
		t.Fatal("peer validation failed")
	}
}

func TestICMPProbeDoesNotOpenSocketAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := probeICMP(ctx, netip.MustParseAddr("127.0.0.1"), "ip4:icmp"); r.Outcome != Unmeasured || r.Reason != "canceled" {
		t.Fatalf("canceled probe: %#v", r)
	}
}

type controlledICMPRunner struct {
	onRecv  func(*probing.Packet)
	run     func(context.Context, *controlledICMPRunner) error
	stats   probing.Statistics
	stopped bool
}

func (p *controlledICMPRunner) RunWithContext(ctx context.Context) error { return p.run(ctx, p) }
func (p *controlledICMPRunner) Stop()                                    { p.stopped = true }
func (p *controlledICMPRunner) Statistics() *probing.Statistics          { return &p.stats }
func (p *controlledICMPRunner) SetOnRecv(f func(*probing.Packet))        { p.onRecv = f }

func TestICMPAdapterAcceptsZeroRTTAndRejectsOtherPeers(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer string
		rtt  time.Duration
		want Outcome
	}{
		{"zero RTT", "192.0.2.1", 0, Success},
		{"normal RTT", "192.0.2.1", time.Millisecond, Success},
		{"different peer", "192.0.2.2", time.Millisecond, Failed},
		{"negative RTT", "192.0.2.1", -time.Nanosecond, Failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &controlledICMPRunner{stats: probing.Statistics{PacketsSent: 1}}
			p.run = func(_ context.Context, p *controlledICMPRunner) error {
				p.onRecv(&probing.Packet{IPAddr: &net.IPAddr{IP: net.ParseIP(tc.peer)}, Rtt: tc.rtt})
				return nil
			}
			r := runICMP(context.Background(), testIP, p)
			if r.Outcome != tc.want || (tc.want == Success && r.RTT != tc.rtt) || !p.stopped {
				t.Fatalf("adapter result=%#v stopped=%v", r, p.stopped)
			}
		})
	}
}

func TestICMPAdapterCancelsAndJoinsRunner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		joined := false
		p := &controlledICMPRunner{}
		p.run = func(ctx context.Context, _ *controlledICMPRunner) error {
			<-ctx.Done()
			joined = true
			return ctx.Err()
		}
		done := make(chan Result, 1)
		go func() { done <- runICMP(ctx, testIP, p) }()
		synctest.Wait()
		cancel()
		r := <-done
		if r.Outcome != Unmeasured || r.Reason != "canceled" || !joined || !p.stopped {
			t.Fatalf("cancel result=%#v joined=%v stopped=%v", r, joined, p.stopped)
		}
	})
}

func TestICMPAdapterSetupErrorIsNotNetworkFailure(t *testing.T) {
	p := &controlledICMPRunner{run: func(context.Context, *controlledICMPRunner) error {
		return errors.New("local socket unavailable")
	}}
	if r := runICMP(context.Background(), testIP, p); r.Outcome != Unmeasured || r.Reason != "icmp_unavailable" {
		t.Fatalf("setup failure: %#v", r)
	}
}

func TestICMPAdapterRejectsReplyAfterCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint("deadline=", deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
				}
				defer cancel()
				reported := false
				ctx = context.WithValue(ctx, probeReporterKey{}, func(Result) { reported = true })
				p := &controlledICMPRunner{stats: probing.Statistics{PacketsSent: 1}}
				p.run = func(_ context.Context, p *controlledICMPRunner) error {
					if deadline {
						time.Sleep(2 * time.Millisecond)
					} else {
						cancel()
					}
					p.onRecv(&probing.Packet{IPAddr: &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, Rtt: time.Millisecond})
					return nil
				}
				r := runICMP(ctx, testIP, p)
				want := Unmeasured
				if deadline {
					want = Failed
				}
				if r.Outcome != want || reported || !p.stopped {
					t.Fatalf("late callback result=%#v reported=%v stopped=%v", r, reported, p.stopped)
				}
			})
		})
	}
}

// This is deliberately a local Linux integration check: opening a ping socket
// alone does not establish that kernel ID rewriting and reply matching work.
// It requires no external host and skips only unavailable platform/capability.
func TestLinuxLocalICMPEcho(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ping-socket integration test")
	}
	m := NewManager(Options{})
	defer m.Close()
	c, err := m.Prepare(Config{TCPPorts: []uint16{}, ICMP: true, Timeout: time.Second})
	if err != nil {
		t.Skipf("ICMP socket capability unavailable: %v", err)
	}
	for _, family := range []struct{ name, ip, network string }{
		{"IPv4", "127.0.0.1", m.icmp4},
		{"IPv6", "::1", m.icmp6},
	} {
		t.Run(family.name, func(t *testing.T) {
			if family.network == "" {
				t.Skip("no ICMP socket for this address family")
			}
			t.Logf("testing %s echo through %s", family.ip, family.network)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r := m.Measure(ctx, netip.MustParseAddr(family.ip), c)
			if r.Outcome != Success || r.Cached || r.RTT < 0 {
				t.Fatalf("local ICMP echo: %#v", r)
			}
		})
	}
}
