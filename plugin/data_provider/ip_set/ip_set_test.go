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

package ip_set

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func appendCIDR(b []byte, ip []byte, prefix uint64) []byte {
	c := protowire.AppendTag(nil, 1, protowire.BytesType)
	c = protowire.AppendBytes(c, ip)
	c = protowire.AppendTag(c, 2, protowire.VarintType)
	c = protowire.AppendVarint(c, prefix)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendBytes(b, c)
}

func appendIPEntry(b []byte, code string, cidrs []byte, reverseMatch bool) []byte {
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

// loadIPs loads ips and returns a matcher matching them.
func loadIPs(t *testing.T, ips []string) MatcherGroup {
	t.Helper()
	loader := NewListLoader()
	if err := loader.LoadFromIPsAndFiles(ips, nil); err != nil {
		t.Fatal(err)
	}
	return MatcherGroup(loader.Matchers())
}

func TestLoadFromIPsGeoip(t *testing.T) {
	var cn, other []byte
	cn = appendCIDR(cn, []byte{1, 2, 3, 0}, 24)
	cn = appendCIDR(cn, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, 64)
	other = appendCIDR(other, []byte{9, 9, 9, 9}, 32)

	var list []byte
	list = appendIPEntry(list, "CN", cn, false)
	list = appendIPEntry(list, "OTHER", other, false)
	datPath := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(datPath, list, 0644); err != nil {
		t.Fatal(err)
	}

	mg := loadIPs(t, []string{
		"ext:" + datPath + ":cn", // the code is compared case-insensitively
		"1.1.1.1",                // plain ip mixed with geoip exps
	})

	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"1.2.4.1", false},
		{"2001:db8::1", true},
		{"2001:db8::2", true},
		{"2001:db9::1", false},
		{"9.9.9.9", false}, // in the OTHER entry, not loaded
		{"1.1.1.1", true},
		{"1.1.1.2", false},
	}
	for _, tt := range tests {
		if got := mg.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// TestLoadFromIPsGeoipSharedMatcher verifies that duplicate geoip
// expressions reuse one shared matcher instance.
func TestLoadFromIPsGeoipSharedMatcher(t *testing.T) {
	var cn []byte
	cn = appendCIDR(cn, []byte{1, 2, 3, 0}, 24)
	list := appendIPEntry(nil, "CN", cn, false)
	datPath := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(datPath, list, 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewListLoader()
	if err := loader.LoadFromIPsAndFiles([]string{
		"ext:" + datPath + ":cn",
		"ext:" + datPath + ":CN", // same entry, different case
		"ext:" + datPath + ":cn", // duplicate
	}, nil); err != nil {
		t.Fatal(err)
	}
	ms := loader.Matchers()
	if len(ms) != 1 {
		t.Fatalf("got %d matchers, want 1 shared", len(ms))
	}

	// Another loader for the same entry gets the same instance.
	loader2 := NewListLoader()
	if err := loader2.LoadFromIPsAndFiles([]string{"ext:" + datPath + ":cn"}, nil); err != nil {
		t.Fatal(err)
	}
	ms2 := loader2.Matchers()
	if len(ms2) != 1 || ms2[0] != ms[0] {
		t.Fatal("expected the same shared matcher instance")
	}
}

func TestLoadFromIPsGeoipErrors(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"missing file", "ext:" + filepath.Join(t.TempDir(), "nonexistent.dat") + ":cn"},
		{"code not found", "ext:" + writeEmptyDat(t) + ":no-such-code"},
		{"reverse match", "!geoip:cn"},
		{"reverse match in code", "geoip:!cn"},
		{"invalid asn", "asn:google"},
		{"no default asn db", "asn:13335"}, // no ASN.mmdb in the test working dir
		{"no default geoip db", "geoip:cn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewListLoader()
			if err := loader.LoadFromIPsAndFiles([]string{tt.ip}, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func writeEmptyDat(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "empty.dat")
	if err := os.WriteFile(p, appendIPEntry(nil, "CN", nil, false), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}
