//go:build windows

package speedtest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	probing "github.com/prometheus-community/pro-bing"
)

// Check actual process privileges rather than inferring raw ICMP support from
// the Linux tests. No elevation or external network access is requested.
func TestWindowsICMPCapabilityAndLocalEcho(t *testing.T) {
	t.Logf("process elevated: %v", windows.GetCurrentProcessToken().IsElevated())
	m := NewManager(Options{})
	defer m.Close()
	c, err := m.Prepare(Config{ICMP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("raw IPv4=%q IPv6=%q; capability diagnostics: %v", m.icmp4, m.icmp6, m.capErr)
	if m.icmp4 == "" && m.icmp6 == "" {
		if c.ICMP || len(c.TCPPorts) != 2 {
			t.Fatal("unavailable ICMP did not retain default TCP")
		}
		if _, err := m.Prepare(Config{ICMP: true, TCPPorts: []uint16{}}); err == nil {
			t.Fatal("ICMP-only startup accepted without raw socket capability")
		}
		t.Log("verified TCP fallback and ICMP-only startup error; raw echo unavailable in this process")
		return
	}
	for _, family := range []struct{ name, ip, network string }{
		{"IPv4", "127.0.0.1", m.icmp4}, {"IPv6", "::1", m.icmp6},
	} {
		t.Run(family.name, func(t *testing.T) {
			if family.network == "" {
				t.Skip("raw ICMP family unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r := m.Measure(ctx, netip.MustParseAddr(family.ip), Config{ICMP: true, TCPPorts: []uint16{}, Timeout: time.Second})
			if r.Outcome != Success {
				t.Fatalf("raw loopback echo failed: %+v", r)
			}
			t.Logf("pro-bing raw loopback echo RTT %s", r.RTT)
			// Exercise the actual one-shot adapter as well as the manager's early
			// result path. Run returns only after its sender/receiver have joined.
			ip := netip.MustParseAddr(family.ip)
			p := newICMPPinger(ip, family.network)
			sent := 0
			p.OnSend = func(*probing.Packet) { sent++ }
			r = runICMP(ctx, ip, proBingRunner{p})
			if r.Outcome != Success || r.RTT < 0 || sent != 1 || len(p.Statistics().Rtts) != 0 || len(p.Statistics().TTLs) != 0 {
				t.Fatalf("one-shot pro-bing result=%#v sent=%d stats=%#v", r, sent, p.Statistics())
			}
		})
	}
}
