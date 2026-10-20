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

package geodata

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildDomain appends an encoded GeoSite.domain (field 2) to b.
func buildDomain(b []byte, t DomainType, value string, attrs ...string) []byte {
	d := protowire.AppendTag(nil, 1, protowire.VarintType)
	d = protowire.AppendVarint(d, uint64(t))
	d = protowire.AppendTag(d, 2, protowire.BytesType)
	d = protowire.AppendString(d, value)
	for _, attr := range attrs {
		a := protowire.AppendTag(nil, 1, protowire.BytesType)
		a = protowire.AppendString(a, attr)
		d = protowire.AppendTag(d, 3, protowire.BytesType)
		d = protowire.AppendBytes(d, a)
	}
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendBytes(b, d)
}

// buildSiteEntry appends an encoded GeoSiteList.entry (field 1) to b. domains
// must be built by buildDomain and already carry their own field tags.
func buildSiteEntry(b []byte, code string, domains []byte) []byte {
	e := protowire.AppendTag(nil, 1, protowire.BytesType)
	e = protowire.AppendString(e, code)
	e = append(e, domains...)
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	return protowire.AppendBytes(b, e)
}

// buildCIDR appends an encoded GeoIP.cidr (field 2) to b.
func buildCIDR(b []byte, ip []byte, prefix uint64) []byte {
	c := protowire.AppendTag(nil, 1, protowire.BytesType)
	c = protowire.AppendBytes(c, ip)
	c = protowire.AppendTag(c, 2, protowire.VarintType)
	c = protowire.AppendVarint(c, prefix)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendBytes(b, c)
}

// buildIPEntry appends an encoded GeoIPList.entry (field 1) to b. cidrs must
// be built by buildCIDR and already carry their own field tags. reverseMatch
// sets the reverse_match field (field 3), which the loader ignores.
func buildIPEntry(b []byte, code string, cidrs []byte, reverseMatch bool) []byte {
	e := protowire.AppendTag(nil, 1, protowire.BytesType)
	e = protowire.AppendString(e, code)
	e = append(e, cidrs...)
	if reverseMatch {
		e = protowire.AppendTag(e, 3, protowire.VarintType)
		e = protowire.AppendVarint(e, 1)
	}
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	return protowire.AppendBytes(b, e)
}

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.dat")
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

type domainEntry struct {
	t     DomainType
	value string
}

func collectDomains(t *testing.T, file, code string, attrs []string) []domainEntry {
	t.Helper()
	var got []domainEntry
	if err := LoadSite(file, code, attrs, func(typ DomainType, value string) error {
		got = append(got, domainEntry{t: typ, value: value})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func compareEntries(t *testing.T, got, want []domainEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected number of entries, got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry #%d mismatch, got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestLoadSite(t *testing.T) {
	var other, cn []byte
	other = buildDomain(other, TypeFull, "other.com")
	cn = buildDomain(cn, TypeFull, "example.com")
	cn = buildDomain(cn, TypeDomain, "qq.com")
	cn = buildDomain(cn, TypeSubstr, "baidu")
	cn = buildDomain(cn, TypeRegex, `^taobao$`)

	var list []byte
	list = buildSiteEntry(list, "OTHER", other)
	list = buildSiteEntry(list, "CN", cn)
	file := writeFile(t, list)

	want := []domainEntry{
		{TypeFull, "example.com"},
		{TypeDomain, "qq.com"},
		{TypeSubstr, "baidu"},
		{TypeRegex, `^taobao$`},
	}

	got := collectDomains(t, file, "cn", nil)
	compareEntries(t, got, want)

	// The code is compared case-insensitively, in both directions.
	got = collectDomains(t, file, "CN", nil)
	compareEntries(t, got, want)
}

func TestLoadLongCode(t *testing.T) {
	code := strings.Repeat("A", 128)
	siteFile := writeFile(t, buildSiteEntry(nil, code, buildDomain(nil, TypeFull, "example.com")))
	compareEntries(t, collectDomains(t, siteFile, strings.ToLower(code), nil), []domainEntry{{TypeFull, "example.com"}})
	ipFile := writeFile(t, buildIPEntry(nil, code, buildCIDR(nil, []byte{1, 2, 3, 0}, 24), false))
	prefixes, err := LoadIP(ipFile, strings.ToLower(code))
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix("1.2.3.0/24") {
		t.Fatalf("unexpected prefixes: %v", prefixes)
	}
}

func TestLoadSiteLowerCaseCodeInFile(t *testing.T) {
	var cn []byte
	cn = buildDomain(cn, TypeDomain, "qq.com")
	list := buildSiteEntry(nil, "cn", cn)
	file := writeFile(t, list)

	got := collectDomains(t, file, "CN", nil)
	compareEntries(t, got, []domainEntry{{TypeDomain, "qq.com"}})
}

func TestLoadSiteAttrs(t *testing.T) {
	var cn []byte
	cn = buildDomain(cn, TypeDomain, "a.com", "cn")
	cn = buildDomain(cn, TypeDomain, "b.com", "ads")
	cn = buildDomain(cn, TypeDomain, "c.com", "cn", "ads")
	cn = buildDomain(cn, TypeDomain, "d.com")
	list := buildSiteEntry(nil, "CN", cn)
	file := writeFile(t, list)

	compareEntries(t, collectDomains(t, file, "cn", nil),
		[]domainEntry{{TypeDomain, "a.com"}, {TypeDomain, "b.com"}, {TypeDomain, "c.com"}, {TypeDomain, "d.com"}})

	compareEntries(t, collectDomains(t, file, "cn", []string{"cn"}),
		[]domainEntry{{TypeDomain, "a.com"}, {TypeDomain, "c.com"}})

	// Multiple attrs have AND semantics.
	compareEntries(t, collectDomains(t, file, "cn", []string{"cn", "ads"}),
		[]domainEntry{{TypeDomain, "c.com"}})

	compareEntries(t, collectDomains(t, file, "cn", []string{"nonexistent"}), nil)
}

func TestLoadSiteNotFound(t *testing.T) {
	list := buildSiteEntry(nil, "CN", nil)
	file := writeFile(t, list)
	err := LoadSite(file, "us", nil, func(t DomainType, value string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error, got %v", err)
	}

	// An empty file contains no entry at all.
	emptyFile := writeFile(t, nil)
	err = LoadSite(emptyFile, "cn", nil, func(t DomainType, value string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error, got %v", err)
	}
}

func TestLoadSiteFnError(t *testing.T) {
	var cn []byte
	cn = buildDomain(cn, TypeFull, "a.com")
	cn = buildDomain(cn, TypeFull, "b.com")
	list := buildSiteEntry(nil, "CN", cn)
	file := writeFile(t, list)

	wantErr := errors.New("test error")
	var n int
	err := LoadSite(file, "cn", nil, func(t DomainType, value string) error {
		n++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error, got %v", err)
	}
	if n != 1 {
		t.Fatalf("fn was called %d times, want 1", n)
	}
}

func TestLoadIP(t *testing.T) {
	var other, cn []byte
	other = buildCIDR(other, []byte{9, 9, 9, 9}, 32)
	cn = buildCIDR(cn, []byte{1, 2, 3, 0}, 24)
	cn = buildCIDR(cn, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, 64)

	var list []byte
	list = buildIPEntry(list, "OTHER", other, false)
	list = buildIPEntry(list, "CN", cn, true) // reverse_match is ignored
	file := writeFile(t, list)

	got, err := LoadIP(file, "cn")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("2001:db8::1/64"),
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected prefixes, got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prefix #%d mismatch, got %v, want %v", i, got[i], want[i])
		}
	}

	// The code is compared case-insensitively.
	if _, err := LoadIP(file, "CN"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIPNotFound(t *testing.T) {
	list := buildIPEntry(nil, "CN", nil, false)
	file := writeFile(t, list)
	_, err := LoadIP(file, "us")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error, got %v", err)
	}
}

func TestLoadSiteMalformed(t *testing.T) {
	// Truncated file: the entry claims a body longer than the file.
	file := writeFile(t, []byte{0x0a, 0xff, 0x0a, 0x02, 'c'})
	err := LoadSite(file, "cn", nil, func(t DomainType, value string) error { return nil })
	if err == nil || strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error, got %v", err)
	}

	// Zero-length entry body is invalid.
	file = writeFile(t, []byte{0x0a, 0x00})
	err = LoadSite(file, "cn", nil, func(t DomainType, value string) error { return nil })
	if err == nil || strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error, got %v", err)
	}

	// Invalid UTF-8 in a domain value.
	var cn []byte
	cn = protowire.AppendTag(cn, 1, protowire.VarintType)
	cn = protowire.AppendVarint(cn, uint64(TypeFull))
	cn = protowire.AppendTag(cn, 2, protowire.BytesType)
	cn = append(cn, 0xff, 0xfe) // AppendString with invalid utf-8 would panic
	list := buildSiteEntry(nil, "CN", cn)
	file = writeFile(t, list)
	err = LoadSite(file, "cn", nil, func(t DomainType, value string) error { return nil })
	if err == nil {
		t.Fatal("expected error for invalid utf-8 value")
	}
}

func TestLoadIPMalformed(t *testing.T) {
	// A v4 cidr with an out-of-range prefix.
	var cn []byte
	cn = buildCIDR(cn, []byte{1, 2, 3, 0}, 33)
	list := buildIPEntry(nil, "CN", cn, false)
	file := writeFile(t, list)
	if _, err := LoadIP(file, "cn"); err == nil {
		t.Fatal("expected error for invalid prefix")
	}

	// A cidr with an invalid ip length.
	var cn2 []byte
	cn2 = buildCIDR(cn2, []byte{1, 2, 3, 4, 5}, 24)
	list = buildIPEntry(nil, "CN", cn2, false)
	file = writeFile(t, list)
	if _, err := LoadIP(file, "cn"); err == nil {
		t.Fatal("expected error for invalid ip length")
	}
}

func TestParseDomainExp(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		file  string
		code  string
		attrs []string
		ok    bool
		err   bool
	}{
		{name: "geosite", s: "geosite:cn", file: "geosite.dat", code: "cn", ok: true},
		{name: "geosite tag", s: "geosite:category-ads-all", file: "geosite.dat", code: "category-ads-all", ok: true},
		{name: "geosite attr", s: "geosite:category-ads-all@cn", file: "geosite.dat", code: "category-ads-all", attrs: []string{"cn"}, ok: true},
		{name: "geosite attrs lowercased", s: "geosite:tag@CN@Ads", file: "geosite.dat", code: "tag", attrs: []string{"cn", "ads"}, ok: true},
		{name: "ext", s: "ext:my.dat:tag", file: "my.dat", code: "tag", ok: true},
		{name: "ext attr", s: "ext:my.dat:tag@x@y", file: "my.dat", code: "tag", attrs: []string{"x", "y"}, ok: true},
		{name: "ext-domain", s: "ext-domain:my.dat:tag", file: "my.dat", code: "tag", ok: true},
		{name: "ext-site", s: "ext-site:my.dat:tag", file: "my.dat", code: "tag", ok: true},
		{name: "windows path", s: `ext:C:\rule\geo.dat:cn`, file: `C:\rule\geo.dat`, code: "cn", ok: true},

		{name: "full", s: "full:example.com", ok: false},
		{name: "domain", s: "domain:qq.com", ok: false},
		{name: "regexp", s: "regexp:.*", ok: false},
		{name: "keyword", s: "keyword:baidu", ok: false},
		{name: "plain", s: "example.com", ok: false},

		{name: "reverse", s: "!geosite:cn", err: true},
		{name: "missing code", s: "ext:my.dat", err: true},
		{name: "empty code", s: "ext:my.dat:", err: true},
		{name: "empty file", s: "ext::cn", err: true},
		{name: "empty code with attr", s: "geosite:@cn", err: true},
		{name: "trailing at", s: "geosite:cn@", err: true},
		{name: "double at", s: "ext:my.dat:cn@@x", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, code, attrs, ok, err := ParseDomainExp(tt.s)
			if tt.err {
				if ok != true || err == nil {
					t.Fatalf("expected error, got ok=%v err=%v", ok, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok != tt.ok {
				t.Fatalf("ok mismatch, got %v, want %v", ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if file != tt.file || code != tt.code {
				t.Fatalf("file/code mismatch, got %q %q, want %q %q", file, code, tt.file, tt.code)
			}
			if len(attrs) != len(tt.attrs) {
				t.Fatalf("attrs mismatch, got %v, want %v", attrs, tt.attrs)
			}
			for i := range attrs {
				if attrs[i] != tt.attrs[i] {
					t.Fatalf("attrs mismatch, got %v, want %v", attrs, tt.attrs)
				}
			}
		})
	}
}

func TestParseIPExp(t *testing.T) {
	tests := []struct {
		name string
		s    string
		file string
		code string
		ok   bool
		err  bool
	}{
		{name: "geoip", s: "geoip:cn", code: "cn", ok: true},
		{name: "ext", s: "ext:geoip.dat:telegram", file: "geoip.dat", code: "telegram", ok: true},
		{name: "ext-ip", s: "ext-ip:a.dat:t", file: "a.dat", code: "t", ok: true},
		{name: "windows path", s: `ext:C:\rule\geoip.dat:cn`, file: `C:\rule\geoip.dat`, code: "cn", ok: true},

		{name: "plain ip", s: "1.2.3.4", ok: false},
		{name: "cidr", s: "1.2.3.0/24", ok: false},
		{name: "v6", s: "2001:db8::1", ok: false},

		{name: "reverse", s: "!geoip:cn", err: true},
		{name: "reverse in code", s: "geoip:!cn", err: true},
		{name: "missing code", s: "ext:a.dat", err: true},
		{name: "empty code", s: "ext:a.dat:", err: true},
		{name: "empty file", s: "ext::cn", err: true},
		{name: "empty code geoip", s: "geoip:", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, _, code, ok, err := ParseIPExp(tt.s)
			if tt.err {
				if ok != true || err == nil {
					t.Fatalf("expected error, got ok=%v err=%v", ok, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok != tt.ok {
				t.Fatalf("ok mismatch, got %v, want %v", ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if file != tt.file || code != tt.code {
				t.Fatalf("file/code mismatch, got %q %q, want %q %q", file, code, tt.file, tt.code)
			}
		})
	}
}
