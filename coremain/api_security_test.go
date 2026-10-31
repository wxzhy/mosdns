package coremain

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtectAPI(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	tests := []struct {
		name   string
		token  string
		remote string
		auth   string
		origin string
		want   int
	}{
		{"local without token", "", "127.0.0.1:1234", "", "", 204},
		{"ipv6 loopback", "", "[::1]:1234", "", "", 204},
		{"remote without token", "", "192.0.2.1:1234", "", "", 403},
		{"remote without address", "", "", "", "", 403},
		{"remote with token", "correct", "192.0.2.1:1234", "Bearer correct", "", 204},
		{"local with token requires authentication", "correct", "127.0.0.1:1234", "", "", 401},
		{"remote wrong token", "correct", "192.0.2.1:1234", "Bearer wrong", "", 401},
		{"cross origin on loopback", "", "127.0.0.1:1234", "", "https://attacker.example", 403},
		{"same origin local", "", "127.0.0.1:1234", "", "http://localhost", 204},
		{"cross origin with token", "correct", "192.0.2.1:1234", "Bearer correct", "https://attacker.example", 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost/cache/clear", nil)
			req.RemoteAddr = tc.remote
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			ProtectAPI(backend, tc.token).ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("got HTTP %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestProtectAPIRejectsDNSRebindingHost(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, tc := range []struct {
		host, token, authorization string
		want                       int
	}{
		{"rebind.attacker.example:9091", "", "", http.StatusForbidden},
		{"127.0.0.1:9091", "", "", http.StatusNoContent},
		{"[::1]:9091", "", "", http.StatusNoContent},
		{"localhost:9091", "", "", http.StatusNoContent},
		{"example.local:9091", "", "", http.StatusForbidden},
		{"rebind.attacker.example:9091", "secret", "Bearer secret", http.StatusNoContent},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://localhost/cache/clear", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Host = tc.host
		r.Header.Set("Origin", "http://"+tc.host)
		r.Header.Set("Authorization", tc.authorization)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		ProtectAPI(backend, tc.token).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("Host %q token=%v: status %d, want %d", tc.host, tc.token != "", w.Code, tc.want)
		}
	}
}
