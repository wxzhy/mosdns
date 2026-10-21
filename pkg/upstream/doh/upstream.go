/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

const (
	defaultDoHTimeout = time.Second * 6
)

var nopLogger = zap.NewNop()

// Upstream is a DNS-over-HTTPS (RFC 8484) upstream.
type Upstream struct {
	rt          http.RoundTripper
	logger      *zap.Logger // non-nil
	urlTemplate *urlpkg.URL
	reqTemplate *http.Request
}

// Options controls DoH HTTP framing without changing the endpoint or TLS SNI.
type Options struct {
	HTTPHost   string
	HTTPMethod string // GET (default) or POST.
}

func NewUpstream(endPoint string, rt http.RoundTripper, logger *zap.Logger) (*Upstream, error) {
	return NewUpstreamWithOptions(endPoint, rt, logger, Options{})
}

func NewUpstreamWithOptions(endPoint string, rt http.RoundTripper, logger *zap.Logger, opt Options) (*Upstream, error) {
	method := strings.ToUpper(strings.TrimSpace(opt.HTTPMethod))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, fmt.Errorf("unsupported DoH HTTP method %q: expected GET or POST", opt.HTTPMethod)
	}
	if opt.HTTPHost != "" && !httpguts.ValidHostHeader(opt.HTTPHost) {
		return nil, fmt.Errorf("invalid DoH HTTP host %q", opt.HTTPHost)
	}
	req, err := http.NewRequest(method, endPoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse http request, %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}
	req.Header["User-Agent"] = nil // Don't let go http send a default user agent header.
	if opt.HTTPHost != "" {
		req.Host = opt.HTTPHost
	}
	if method == http.MethodPost {
		req.Header["Content-Type"] = []string{"application/dns-message"}
	}

	if logger == nil {
		logger = nopLogger
	}
	return &Upstream{
		rt:          rt,
		logger:      logger,
		urlTemplate: req.URL,
		reqTemplate: req,
	}, nil
}

var (
	bufPool4k = pool.NewBytesBufPool(4096)
)

func (u *Upstream) Close() error {
	if closer, ok := u.rt.(io.Closer); ok {
		return closer.Close()
	}
	if closer, ok := u.rt.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

func (u *Upstream) ExchangeContext(ctx context.Context, q []byte) (*[]byte, error) {
	if len(q) < dnsutils.DnsHeaderLen {
		return nil, dnsutils.ErrPayloadTooSmall
	}
	id := binary.BigEndian.Uint16(q)
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484#section-4.1
	var dnsQuery string
	var body []byte
	if u.reqTemplate.Method == http.MethodPost {
		// RoundTripper may consume/close Body after returning, including after
		// cancellation. Keep its bytes independent of callers and buffer pools.
		body = bytes.Clone(q)
		body[0], body[1] = 0, 0
	} else {
		bp := pool.GetBuf(len(q))
		defer pool.ReleaseBuf(bp)
		wire := *bp
		copy(wire, q)
		wire[0], wire[1] = 0, 0
		queryBuf := make([]byte, 4+base64.RawURLEncoding.EncodedLen(len(wire)))
		copy(queryBuf, "dns=")
		// RFC 8484 section 6 forbids base64url padding.
		base64.RawURLEncoding.Encode(queryBuf[4:], wire)
		dnsQuery = utils.BytesToStringUnsafe(queryBuf)
	}

	if query_policy.InheritCancellation(ctx) {
		requestCtx, cancel := context.WithTimeout(ctx, defaultDoHTimeout)
		defer cancel()
		r, err := u.exchange(requestCtx, dnsQuery, body)
		if err != nil {
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
			return nil, err
		}
		binary.BigEndian.PutUint16(*r, id)
		return r, nil
	}

	type res struct {
		r   *[]byte
		err error
	}

	resChan := make(chan res)
	done := make(chan struct{})
	defer close(done)
	go func() {
		// We overwrite the ctx with a fixed timeout context here.
		// Because the http package may close the underlay connection
		// if the context is done before the query is completed. This
		// reduces the connection reuse efficiency.
		ctx, cancel := context.WithTimeout(context.Background(), defaultDoHTimeout)
		defer cancel()
		r, err := u.exchange(ctx, dnsQuery, body)
		if err != nil {
			u.logger.Check(zap.WarnLevel, "exchange failed").Write(zap.Error(err))
		}
		select {
		case resChan <- res{r: r, err: err}:
		case <-done:
			if r != nil {
				pool.ReleaseBuf(r)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case res := <-resChan:
		r := res.r
		err := res.err
		if r != nil {
			binary.BigEndian.PutUint16(*r, id)
		}
		return r, err
	}
}

func (u *Upstream) exchange(ctx context.Context, dnsQuery string, body []byte) (*[]byte, error) {
	req := u.reqTemplate.WithContext(ctx)
	req.URL = new(urlpkg.URL)
	*req.URL = *u.urlTemplate
	if req.Method == http.MethodPost {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	} else if req.URL.RawQuery == "" {
		req.URL.RawQuery = dnsQuery
	} else {
		params := req.URL.Query()
		params.Set("dns", strings.TrimPrefix(dnsQuery, "dns="))
		req.URL.RawQuery = params.Encode()
	}
	resp, err := u.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		body1k, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if body1k != nil {
			return nil, fmt.Errorf("bad http status codes %d with body [%s]", resp.StatusCode, body1k)
		}
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	bb := bufPool4k.Get()
	defer bufPool4k.Release(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}
	if bb.Len() < dnsutils.DnsHeaderLen {
		return nil, dnsutils.ErrPayloadTooSmall
	}
	if bb.Len() > dns.MaxMsgSize {
		return nil, fmt.Errorf("DoH response exceeds DNS message size")
	}
	m := new(dns.Msg)
	if err := m.Unpack(bb.Bytes()); err != nil {
		return nil, fmt.Errorf("invalid DoH response: %w", err)
	}
	if !m.Response || m.Id != 0 {
		return nil, fmt.Errorf("invalid DoH response header")
	}
	// RFC 8484 section 5.1: an HTTP cache's Age consumes DNS TTL.
	// Preserve zero TTL rather than using SubtractTTL's one-second floor.
	if age, err := strconv.ParseUint(strings.TrimSpace(resp.Header.Get("Age")), 10, 64); err == nil && age > 0 {
		for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
			for _, rr := range section {
				if rr.Header().Rrtype == dns.TypeOPT {
					continue
				}
				if age >= uint64(rr.Header().Ttl) {
					rr.Header().Ttl = 0
				} else {
					rr.Header().Ttl -= uint32(age)
				}
			}
		}
		return pool.PackBuffer(m)
	}
	payload := pool.GetBuf(bb.Len())
	copy(*payload, bb.Bytes())
	return payload, nil
}
