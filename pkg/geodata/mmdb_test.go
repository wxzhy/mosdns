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
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/geodata/internal/mmdbbuild"
)

func mustPfx(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func addPrefix(t *testing.T, w *mmdbbuild.Writer, prefix string, record []byte) {
	t.Helper()
	if err := w.Add(mustPfx(prefix), record); err != nil {
		t.Fatal(err)
	}
}

func writeMMDB(t *testing.T, w *mmdbbuild.Writer) string {
	t.Helper()
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// geoLite2CountryRecord encodes a GeoLite2 style country record.
func geoLite2CountryRecord(isoCode string) []byte {
	return mmdbbuild.Map(
		mmdbbuild.F("country", mmdbbuild.Map(
			mmdbbuild.F("iso_code", mmdbbuild.String(isoCode)),
		)),
	)
}

func geoLite2ASNRecord(asn uint32, org string) []byte {
	return mmdbbuild.Map(
		mmdbbuild.F("autonomous_system_number", mmdbbuild.Uint32(asn)),
		mmdbbuild.F("autonomous_system_organization", mmdbbuild.String(org)),
	)
}

func TestIsMMDBFile(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-Country", 6)
	addPrefix(t, w, "1.2.0.0/16", geoLite2CountryRecord("CN"))
	if !isMMDBFile(writeMMDB(t, w)) {
		t.Error("expected an mmdb file")
	}

	// A dat file is not an mmdb file.
	list := buildSiteEntry(nil, "CN", nil)
	if isMMDBFile(writeFile(t, list)) {
		t.Error("did not expect an mmdb file")
	}
	if isMMDBFile(filepath.Join(t.TempDir(), "missing.mmdb")) {
		t.Error("did not expect an mmdb file")
	}
}

// TestMMDBBuilderRoundTrip verifies the hand-written mmdb builder against
// the real reader, both directly and through the matcher.
func TestMMDBBuilderRoundTrip(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-Country", 6)
	addPrefix(t, w, "1.2.0.0/16", geoLite2CountryRecord("CN"))
	addPrefix(t, w, "2001:db8::/32", geoLite2CountryRecord("US"))
	addPrefix(t, w, "9.9.9.0/24", geoLite2CountryRecord("DE"))
	file := writeMMDB(t, w)

	r, err := openMMDB(file)
	if err != nil {
		t.Fatal(err)
	}
	var rec mmdbCountryRecord
	res := r.Lookup(netip.MustParseAddr("1.2.3.4"))
	if err := res.Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if !res.Found() || rec.Country.IsoCode != "CN" {
		t.Errorf("unexpected lookup result: found=%v %+v", res.Found(), rec)
	}

	m, err := newMMDBCountryMatcher(file, "cn")
	if err != nil {
		t.Fatal(err)
	}
	us, err := newMMDBCountryMatcher(file, "us")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		m    *MMDBIPMatcher
		ip   string
		want bool
	}{
		{m, "1.2.0.0", true},
		{m, "1.2.255.255", true},
		{m, "1.2.3.4", true},
		{m, "1.3.0.1", false},
		{us, "2001:db8::1", true},
		{us, "2001:db9::1", false},
		{m, "2001:db8::1", false},
		{m, "9.9.9.9", false},
		{m, "::ffff:1.2.3.4", true}, // 4-in-6 form is unmapped
	}
	for _, tt := range tests {
		if got := tt.m.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestMMDBCountryMatcherIPv4DB(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-Country", 4)
	addPrefix(t, w, "1.2.0.0/16", geoLite2CountryRecord("CN"))
	file := writeMMDB(t, w)

	m, err := newMMDBCountryMatcher(file, "CN") // the code is case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Error("expected a match")
	}
	if m.Match(netip.MustParseAddr("1.3.0.1")) {
		t.Error("did not expect a match")
	}
}

func TestMMDBCountryMatcherSing(t *testing.T) {
	w := mmdbbuild.New("sing-geoip", 6)
	addPrefix(t, w, "1.2.0.0/16", mmdbbuild.String("cn"))
	file := writeMMDB(t, w)

	m, err := newMMDBCountryMatcher(file, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Error("expected a match")
	}
}

func TestMMDBCountryMatcherMetaV0(t *testing.T) {
	w := mmdbbuild.New("Meta-geoip0", 6)
	addPrefix(t, w, "1.2.0.0/16", mmdbbuild.String("cn"))
	addPrefix(t, w, "1.3.0.0/16", mmdbbuild.Array(mmdbbuild.String("us"), mmdbbuild.String("hk")))
	file := writeMMDB(t, w)

	m, err := newMMDBCountryMatcher(file, "HK")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("1.3.0.1")) {
		t.Error("expected a match from the multi-code record")
	}
	if m.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Error("did not expect a match")
	}
}

func TestMMDBASNMatcher(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-ASN", 6)
	addPrefix(t, w, "1.1.1.0/24", geoLite2ASNRecord(13335, "CLOUDFLARENET"))
	addPrefix(t, w, "8.8.8.0/24", geoLite2ASNRecord(15169, "GOOGLE"))
	addPrefix(t, w, "240e:f7::/32", geoLite2ASNRecord(4134, "CHINANET-BACKBONE"))
	file := writeMMDB(t, w)

	cf, err := newMMDBASNMatcher(file, 13335)
	if err != nil {
		t.Fatal(err)
	}
	gg, err := newMMDBASNMatcher(file, 15169)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		m    *MMDBIPMatcher
		ip   string
		want bool
	}{
		{cf, "1.1.1.1", true},
		{cf, "1.1.2.1", false},
		{cf, "8.8.8.8", false},
		{cf, "::ffff:1.1.1.1", true},
		{gg, "8.8.8.4", true},
		{gg, "8.8.4.4", false},
		{gg, "8.8.255.1", false},
		{cf, "240e:f7:c000:fea::1", false},
	}
	for _, tt := range tests {
		if got := tt.m.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}

	// An asn number of a v6-only network.
	as4134, err := newMMDBASNMatcher(file, 4134)
	if err != nil {
		t.Fatal(err)
	}
	if !as4134.Match(netip.MustParseAddr("240e:f7:1::1")) {
		t.Error("expected a match")
	}
}

func TestMMDBASNMatcherIPInfo(t *testing.T) {
	w := mmdbbuild.New("ipinfo generic_asn_free.mmdb", 6)
	addPrefix(t, w, "1.1.1.0/24", mmdbbuild.Map(
		mmdbbuild.F("asn", mmdbbuild.String("AS13335")),
		mmdbbuild.F("name", mmdbbuild.String("CLOUDFLARENET")),
	))
	file := writeMMDB(t, w)

	m, err := newMMDBASNMatcher(file, 13335)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Error("expected a match")
	}
	if m.Match(netip.MustParseAddr("1.1.2.1")) {
		t.Error("did not expect a match")
	}
}

func TestMMDBASNMatcherUnsupportedType(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-City", 6)
	addPrefix(t, w, "1.1.1.0/24", mmdbbuild.Map())
	file := writeMMDB(t, w)

	if _, err := newMMDBASNMatcher(file, 13335); err == nil {
		t.Fatal("expected an error")
	}
}

func TestGetGeoIPMatcher(t *testing.T) {
	// A maxmind country database.
	w := mmdbbuild.New("GeoLite2-Country", 6)
	addPrefix(t, w, "1.2.0.0/16", geoLite2CountryRecord("CN"))
	mmdbFile := writeMMDB(t, w)

	m1, err := GetGeoIPMatcher(mmdbFile, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if !m1.Match(netip.MustParseAddr("1.2.3.4")) {
		t.Error("expected a match")
	}

	// The matcher is shared.
	m2, err := GetGeoIPMatcher(mmdbFile, "CN")
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Error("expected the same shared matcher instance")
	}

	// A dat file takes the dat path.
	var cn []byte
	cn = buildCIDR(cn, []byte{9, 9, 9, 0}, 24)
	list := buildIPEntry(nil, "CN", cn, false)
	datFile := writeFile(t, list)
	m3, err := GetGeoIPMatcher(datFile, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if !m3.Match(netip.MustParseAddr("9.9.9.9")) {
		t.Error("expected a match")
	}

	// The default-file shortcut finds nothing in the test working dir.
	if _, err := GetGeoIPMatcher("", "cn"); err == nil {
		t.Error("expected an error")
	}
}

func TestGetGeoIPMatcherASNDB(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-ASN", 6)
	addPrefix(t, w, "1.1.1.0/24", geoLite2ASNRecord(13335, "CLOUDFLARENET"))
	file := writeMMDB(t, w)

	// An ext: expression on an asn database dispatches to the asn matcher.
	m, err := GetGeoIPMatcher(file, "13335")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Error("expected a match")
	}

	// A non-numeric code on an asn database is an error.
	if _, err := GetGeoIPMatcher(file, "cn"); err == nil {
		t.Error("expected an error")
	}
}

func TestGetASNMatcher(t *testing.T) {
	w := mmdbbuild.New("GeoLite2-ASN", 6)
	addPrefix(t, w, "1.1.1.0/24", geoLite2ASNRecord(13335, "CLOUDFLARENET"))
	file := writeMMDB(t, w)

	m1, err := GetASNMatcher(file, "13335")
	if err != nil {
		t.Fatal(err)
	}
	if !m1.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Error("expected a match")
	}

	// "AS" prefix and different case parse to the same shared matcher.
	m2, err := GetASNMatcher(file, "AS13335")
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Error("expected the same shared matcher instance")
	}

	if _, err := GetASNMatcher(file, "not-a-number"); err == nil {
		t.Error("expected an error")
	}
	if _, err := GetASNMatcher("", "13335"); err == nil {
		t.Error("expected an error for missing default asn database")
	}

	// A country database is not an asn database.
	cw := mmdbbuild.New("GeoLite2-Country", 6)
	addPrefix(t, cw, "1.2.0.0/16", geoLite2CountryRecord("CN"))
	countryFile := writeMMDB(t, cw)
	if _, err := GetASNMatcher(countryFile, "13335"); err == nil {
		t.Error("expected an error")
	}
}
