package udp_server

import "testing"

func TestArgsDefaults(t *testing.T) {
	a := new(Args)
	a.init()
	if a.Listen != "127.0.0.1:53" {
		t.Fatalf("listen = %q", a.Listen)
	}
	b := &Args{Listen: "127.0.0.1:5353"}
	b.init()
	if b.Listen != "127.0.0.1:5353" {
		t.Fatalf("explicit listen overwritten: %q", b.Listen)
	}
}
