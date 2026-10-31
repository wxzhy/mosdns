# MosDNS management API access

The management API exposes query logs and administrative actions (including
cache clearing and importing statistics). It is **not** intended to be
accessible anonymously from the Internet or an untrusted LAN.

By default, incoming requests to the management HTTP server are accepted
only from loopback addresses. Requests from other addresses receive HTTP 403.
For local access, use `api.http: 127.0.0.1:9091` (as in the SmartDNS examples).
When no token is configured, the HTTP Host must also be `localhost` or a
literal loopback IP address (optionally including its port); arbitrary hostnames
are rejected to mitigate DNS rebinding. Access through a local reverse proxy
using a custom Host should configure a token instead.

Remote management requires a configured token:

```yaml
api:
  http: 0.0.0.0:9091
  token: "provide-a-long-random-secret"
```

With a token, all callers (including localhost) must send the HTTP header
`Authorization: Bearer <token>`. Token authentication is also available for
the separately listening `stats_api` plugin via `args.token`; the main API
token does not automatically configure an independently listening stats API.
The built-in HTTP listener does **not** implement TLS: use an authenticated
HTTPS reverse proxy or a secure tunnel for remote management. Avoid exposing
this listener directly to the public Internet.

Cross-origin browser requests are denied; the previous permissive CORS
headers were removed. A browser dashboard hosted at a different origin should
use an authenticated same-origin reverse proxy instead.
Cache management's `/flush` endpoint now accepts POST, not GET, to avoid
triggering a destructive operation on ordinary link navigation.

A reverse proxy connecting from loopback is treated as a trusted local client
when no token is configured, so the reverse proxy must enforce authentication.
