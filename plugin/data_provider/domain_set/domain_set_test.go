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

package domain_set

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"

	"google.golang.org/protobuf/encoding/protowire"
)

func appendDomain(b []byte, t geodata.DomainType, value string, attrs ...string) []byte {
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

func appendSiteEntry(b []byte, code string, domains []byte) []byte {
	e := protowire.AppendTag(nil, 1, protowire.BytesType)
	e = protowire.AppendString(e, code)
	e = append(e, domains...)
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	return protowire.AppendBytes(b, e)
}

func TestLoadExpsGeosite(t *testing.T) {
	var cn, ads []byte
	cn = appendDomain(cn, geodata.TypeFull, "example.com")
	cn = appendDomain(cn, geodata.TypeDomain, "qq.com")
	cn = appendDomain(cn, geodata.TypeSubstr, "baidu")
	cn = appendDomain(cn, geodata.TypeRegex, `^taobao$`)
	ads = appendDomain(ads, geodata.TypeDomain, "with-attr.com", "cn")
	ads = appendDomain(ads, geodata.TypeFull, "without-attr.com")

	var list []byte
	list = appendSiteEntry(list, "CN", cn)
	list = appendSiteEntry(list, "ADS", ads)
	datPath := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(datPath, list, 0644); err != nil {
		t.Fatal(err)
	}

	m := domain.NewDomainMixMatcher()
	exps := []string{
		"ext:" + datPath + ":cn", // the code is compared case-insensitively
		"ext:" + datPath + ":ads@cn",
		"full:mixed.example",
	}
	if err := LoadExpsAndFiles(exps, nil, m); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		qname string
		want  bool
	}{
		// geosite cn entry
		{"example.com", true},      // full
		{"www.example.com", false}, // full does not match subdomains
		{"qq.com", true},           // domain
		{"www.qq.com", true},       // domain matches subdomains
		{"notqq.com", false},       // domain matches on label boundary only
		{"xbaidux", true},          // keyword
		{"taobao", true},           // regexp
		{"taobao.com", false},      // regexp
		// geosite ads entry, filtered by the @cn attr
		{"with-attr.com", true},     // has the cn attr
		{"www.with-attr.com", true}, // domain type
		{"without-attr.com", false}, // no cn attr, filtered out
		// plain exp mixed with geosite exps
		{"mixed.example", true},
		{"www.mixed.example", false},
	}
	for _, tt := range tests {
		if _, got := m.Match(tt.qname); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.qname, got, tt.want)
		}
	}
}

func TestLoadExpsGeositeWithoutAttrFilter(t *testing.T) {
	var ads []byte
	ads = appendDomain(ads, geodata.TypeDomain, "with-attr.com", "cn")
	ads = appendDomain(ads, geodata.TypeFull, "without-attr.com")
	list := appendSiteEntry(nil, "ADS", ads)
	datPath := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(datPath, list, 0644); err != nil {
		t.Fatal(err)
	}

	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles([]string{"ext:" + datPath + ":ads"}, nil, m); err != nil {
		t.Fatal(err)
	}
	for _, qname := range []string{"with-attr.com", "without-attr.com"} {
		if _, ok := m.Match(qname); !ok {
			t.Errorf("Match(%s) = false, want true", qname)
		}
	}
}

func TestLoadExpsGeositeErrors(t *testing.T) {
	tests := []struct {
		name string
		exp  string
	}{
		{"missing file", "ext:" + filepath.Join(t.TempDir(), "nonexistent.dat") + ":cn"},
		{"code not found", "ext:" + writeEmptyDat(t) + ":no-such-code"},
		{"reverse match", "!geosite:cn"},
		{"empty code", "ext:geosite.dat:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := domain.NewDomainMixMatcher()
			if err := LoadExpsAndFiles([]string{tt.exp}, nil, m); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func writeEmptyDat(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "empty.dat")
	if err := os.WriteFile(p, appendSiteEntry(nil, "CN", nil), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}
