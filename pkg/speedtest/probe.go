package speedtest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func (m *Manager) probeNetwork(ctx context.Context, ip netip.Addr, method probeMethod) Result {
	if method.port != 0 {
		return probeTCP(ctx, ip, method.port)
	}
	network := m.icmp6
	if ip.Is4() {
		network = m.icmp4
	}
	if network == "" {
		return Result{Outcome: Unmeasured, Reason: "icmp_family_unavailable"}
	}
	return probeICMP(ctx, ip, network)
}

func probeTCP(ctx context.Context, ip netip.Addr, port uint16) Result {
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
	rtt := time.Since(start)
	if err != nil {
		return networkFailure(ctx, err)
	}
	_ = conn.Close()
	return Result{Outcome: Success, RTT: rtt}
}

func networkFailure(ctx context.Context, err error) Result {
	if errors.Is(ctx.Err(), context.Canceled) {
		return Result{Outcome: Unmeasured, Reason: "canceled"}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Result{Outcome: Failed, Reason: "timeout"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Result{Outcome: Failed, Reason: "timeout"}
	}
	return Result{Outcome: Failed, Reason: "network_error"}
}

// detectICMP validates a single local echo through the same pro-bing backend
// used for measurements, one socket at a time. Linux first tries datagram ping,
// then raw ICMP. Windows uses pro-bing's recommended privileged mode; its name
// does not imply that elevation is required on every Windows installation.
// Keep the families separate because IPv6 can be disabled independently.
func detectICMP() (v4, v6 string, err error) {
	var errs []error
	for _, family := range []int{4, 6} {
		networks := []string{"ip4:icmp"}
		ip := netip.MustParseAddr("127.0.0.1")
		if family == 6 {
			networks, ip = []string{"ip6:ipv6-icmp"}, netip.IPv6Loopback()
		}
		if runtime.GOOS == "linux" {
			if family == 4 {
				networks = append([]string{"udp4"}, networks...)
			} else {
				networks = append([]string{"udp6"}, networks...)
			}
		}
		for _, network := range networks {
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			result := probeICMP(ctx, ip, network)
			cancel()
			if result.Outcome != Success {
				errs = append(errs, fmt.Errorf("%s local ICMP capability: %s", network, result.Reason))
				continue
			}
			if family == 4 {
				v4 = network
			} else {
				v6 = network
			}
			break
		}
	}
	return v4, v6, errors.Join(errs...)
}

func newICMPPinger(ip netip.Addr, network string) *probing.Pinger {
	p := probing.New(ip.String())
	// The candidate is already an IP. SetIPAddr avoids a second DNS lookup and
	// preserves an IPv6 interface zone when present.
	p.SetIPAddr(&net.IPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()})
	p.SetPrivileged(!strings.HasPrefix(network, "udp"))
	p.Count = 1
	p.Timeout = 300 * time.Millisecond
	p.RecordRtts = false
	p.RecordTTLs = false
	// Keep packet diagnostics within the measurement policy instead of writing
	// a library log for every unexpected ICMP packet.
	p.SetLogger(probing.NoopLogger{})
	return p
}

// icmpRunner isolates only the library's lifetime and delivery API. Its Run
// method must join callbacks and release its private socket before returning.
type icmpRunner interface {
	RunWithContext(context.Context) error
	Stop()
	Statistics() *probing.Statistics
	SetOnRecv(func(*probing.Packet))
}

type proBingRunner struct{ *probing.Pinger }

func (p proBingRunner) SetOnRecv(f func(*probing.Packet)) { p.OnRecv = f }

func probeICMP(ctx context.Context, ip netip.Addr, network string) Result {
	if err := ctx.Err(); err != nil {
		return unmeasuredContext(err)
	}
	p := newICMPPinger(ip, network)
	if deadline, ok := ctx.Deadline(); ok {
		p.Timeout = time.Until(deadline)
		if p.Timeout <= 0 {
			return Result{Outcome: Unmeasured, Reason: "deadline_exceeded"}
		}
	}
	return runICMP(ctx, ip, proBingRunner{p})
}

func runICMP(ctx context.Context, ip netip.Addr, p icmpRunner) Result {
	if err := ctx.Err(); err != nil {
		return unmeasuredContext(err)
	}
	defer p.Stop()
	result := Result{Outcome: Failed, Reason: "timeout"}
	p.SetOnRecv(func(packet *probing.Packet) {
		if ctx.Err() != nil {
			return
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return
		}
		// pro-bing validates its random tracking UUID and sequence. Still require
		// the requested peer so a redirected/broadcast echo cannot win selection.
		if sameICMPPeer(packet.IPAddr, ip) && packet.Rtt >= 0 {
			result = Result{Outcome: Success, RTT: packet.Rtt}
			reportProbeResult(ctx, result)
			p.Stop()
		}
	})
	err := p.RunWithContext(ctx)
	// RunWithContext joins the library's sender and receiver and closes its
	// private socket before returning. Do not release the physical probe slot
	// earlier, even when Stop needs to wait for the library's read deadline.
	if ctx.Err() != nil {
		return networkFailure(ctx, ctx.Err())
	}
	if result.Outcome == Success {
		return result
	}
	if err != nil {
		if p.Statistics().PacketsSent == 0 {
			// Failed local setup is not evidence that the remote address failed.
			return Result{Outcome: Unmeasured, Reason: "icmp_unavailable"}
		}
		return networkFailure(ctx, err)
	}
	return result
}

func sameICMPPeer(peer *net.IPAddr, ip netip.Addr) bool {
	if peer == nil {
		return false
	}
	a, ok := netip.AddrFromSlice(peer.IP)
	return ok && a.Unmap() == ip.WithZone("").Unmap()
}
