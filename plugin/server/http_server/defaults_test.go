package http_server

import "testing"

func TestArgsDefaults(t *testing.T) {
	a := new(Args)
	a.init()
	if a.IdleTimeout != 30 {
		t.Fatalf("idle timeout = %d, want 30", a.IdleTimeout)
	}
	b := &Args{IdleTimeout: 70}
	b.init()
	if b.IdleTimeout != 70 {
		t.Fatalf("explicit idle timeout overwritten: %d", b.IdleTimeout)
	}
}
