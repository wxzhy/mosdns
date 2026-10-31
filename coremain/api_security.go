package coremain

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ProtectAPI protects management and diagnostic endpoints, not DNS listeners.
// Without a configured token, only loopback clients are allowed; with a token,
// all clients must send Authorization: Bearer <token>. Cross-origin browser
// requests are never allowed to execute state-changing management operations.
// A reverse proxy on loopback must implement its own access control.
func ProtectAPI(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-origin API request denied", http.StatusForbidden)
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
			http.Error(w, "cross-site API request denied", http.StatusForbidden)
			return
		}
		if token != "" {
			provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "API authorization required", http.StatusUnauthorized)
				return
			}
		} else {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			addr, parseErr := netip.ParseAddr(host)
			if err != nil || parseErr != nil || !addr.Unmap().IsLoopback() {
				http.Error(w, "management API is restricted to loopback without a token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
