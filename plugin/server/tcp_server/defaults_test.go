package tcp_server

import "testing"

func TestArgsDefaults(t *testing.T) {
	a := new(Args)
	a.init()
	if a.Listen != "127.0.0.1:53" || a.IdleTimeout != 10 {
		t.Fatalf("defaults = (%q, %d)", a.Listen, a.IdleTimeout)
	}
	b := &Args{Listen: "127.0.0.1:5353", IdleTimeout: 70}
	b.init()
	if b.Listen != "127.0.0.1:5353" || b.IdleTimeout != 70 {
		t.Fatalf("explicit settings overwritten: %+v", b)
	}
}
