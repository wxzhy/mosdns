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
	"testing"
)

func TestGetSiteMatcherShared(t *testing.T) {
	var cn []byte
	cn = buildDomain(cn, TypeDomain, "qq.com")
	list := buildSiteEntry(nil, "CN", cn)
	file := writeFile(t, list)

	m1, err := GetSiteMatcher(file, "cn", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m1.Match("www.qq.com"); !ok {
		t.Error("expected a match")
	}

	// Same entry, different code case: one shared instance.
	m2, err := GetSiteMatcher(file, "CN", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Error("expected the same shared matcher instance")
	}

	// Different attrs load a different matcher.
	m3, err := GetSiteMatcher(file, "CN", []string{"attr"})
	if err != nil {
		t.Fatal(err)
	}
	if m3 == m1 {
		t.Error("did not expect the same instance for different attrs")
	}

	if _, err := GetSiteMatcher(file, "missing-code", nil); err == nil {
		t.Error("expected an error")
	}
}

// TestParseIPExpASN covers the asn: syntax added to ParseIPExp.
func TestParseIPExpASN(t *testing.T) {
	tests := []struct {
		s    string
		file string
		kind IPExpKind
		code string
		ok   bool
		err  bool
	}{
		{s: "asn:13335", kind: IPExpASN, code: "13335", ok: true},
		{s: "asn:AS13335", kind: IPExpASN, code: "AS13335", ok: true},
		{s: "asn:as13335", kind: IPExpASN, code: "as13335", ok: true},
		{s: "ext:GeoLite2-ASN.mmdb:13335", file: "GeoLite2-ASN.mmdb", kind: IPExpGeoIP, code: "13335", ok: true},
		{s: "geoip:cn", kind: IPExpGeoIP, code: "cn", ok: true},

		{s: "1.2.3.4", ok: false},
		{s: "2001:db8::1/64", ok: false},

		{s: "!asn:13335", err: true},
		{s: "asn:google", err: true},
		{s: "asn:", err: true},
		{s: "asn:0x13335", err: true},
		{s: "ext:asn.mmdb:", err: true},
	}
	for _, tt := range tests {
		file, kind, code, ok, err := ParseIPExp(tt.s)
		if tt.err {
			if !ok || err == nil {
				t.Errorf("ParseIPExp(%q): expected error, got ok=%v err=%v", tt.s, ok, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseIPExp(%q): %v", tt.s, err)
			continue
		}
		if ok != tt.ok || file != tt.file || kind != tt.kind || code != tt.code {
			t.Errorf("ParseIPExp(%q) = %q %d %q %v, want %q %d %q %v",
				tt.s, file, kind, code, ok, tt.file, tt.kind, tt.code, tt.ok)
		}
	}
}
