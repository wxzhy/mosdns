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
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"

	"github.com/oschwald/maxminddb-golang/v2"
)

// The maxmind db support and the record layouts of the known database types
// follow mihomo's component/mmdb implementation.

// mmdbMetadataMaxSize is the metadata section size cap in the MaxMind DB
// spec. The metadata start marker only needs to be searched within the last
// 128 KiB of a file.
const mmdbMetadataMaxSize = 128 * 1024

var mmdbMetadataMarker = []byte("\xab\xcd\xefMaxMind.com")

var mmdbReaderCache sync.Map // absolute file path -> *maxminddb.Reader

type mmdbOffsetKey struct {
	r      *maxminddb.Reader
	offset uintptr
}

var mmdbRecordCache sync.Map // mmdbOffsetKey -> string or []string

// openMMDB opens a maxmind db reader from file, or returns the shared,
// already opened one. Readers are cached for the lifetime of the process and
// never closed; maxminddb readers are safe for concurrent lookups.
func openMMDB(file string) (*maxminddb.Reader, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	if v, ok := mmdbReaderCache.Load(abs); ok {
		return v.(*maxminddb.Reader), nil
	}
	r, err := maxminddb.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open maxmind db %s: %w", file, err)
	}
	actual, loaded := mmdbReaderCache.LoadOrStore(abs, r)
	if loaded {
		// Another concurrent loader installed a reader while this one was
		// opening. Only the installed reader lives for the process lifetime.
		_ = r.Close()
	}
	return actual.(*maxminddb.Reader), nil
}

// isMMDBFile reports whether file is a maxmind db, by searching the metadata
// start marker in the last 128 KiB of the file.
func isMMDBFile(file string) bool {
	if abs, err := filepath.Abs(file); err == nil {
		if _, ok := mmdbReaderCache.Load(abs); ok {
			return true
		}
	}
	f, err := os.Open(file) // #nosec G304 -- path comes from the user's config
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return false
	}
	readSize := st.Size()
	if readSize > mmdbMetadataMaxSize {
		readSize = mmdbMetadataMaxSize
	}
	b := make([]byte, readSize)
	if _, err := f.ReadAt(b, st.Size()-readSize); err != nil {
		return false
	}
	return bytes.Contains(b, mmdbMetadataMarker)
}

// mmdbIsASNDB reports whether the database holds asn records, judging from
// its database_type metadata.
func mmdbIsASNDB(r *maxminddb.Reader) bool {
	return strings.Contains(strings.ToUpper(r.Metadata.DatabaseType), "ASN")
}

// Record layouts of the known database types.

type mmdbCountryRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type mmdbASNRecord struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
}

type mmdbIPInfoASNRecord struct {
	ASN string `maxminddb:"asn"` // e.g. "AS13335"
}

const (
	mmdbKindCountry       = iota
	mmdbKindCountrySing   // "sing-geoip": the record is a plain country code string
	mmdbKindCountryMetaV0 // "Meta-geoip0": the record is a string or an array of strings
	mmdbKindASNMaxmind    // "GeoLite2-ASN" and compatibles
	mmdbKindASNIPInfo     // "ipinfo generic_asn_free.mmdb"
)

var _ netlist.Matcher = (*MMDBIPMatcher)(nil)

// MMDBIPMatcher implements netlist.Matcher by looking the address up in a
// maxmind db at match time. All matchers from the same file share one
// underlying reader.
type MMDBIPMatcher struct {
	r    *maxminddb.Reader
	kind int
	code string // lower-cased country code, country kinds
	asn  uint32 // as number, asn kinds
}

func newMMDBCountryMatcher(file, code string) (*MMDBIPMatcher, error) {
	r, err := openMMDB(file)
	if err != nil {
		return nil, err
	}
	m := &MMDBIPMatcher{r: r, code: strings.ToLower(code)}
	switch r.Metadata.DatabaseType {
	case "sing-geoip":
		m.kind = mmdbKindCountrySing
	case "Meta-geoip0":
		m.kind = mmdbKindCountryMetaV0
	default:
		m.kind = mmdbKindCountry
	}
	return m, nil
}

func newMMDBASNMatcher(file string, asn uint32) (*MMDBIPMatcher, error) {
	r, err := openMMDB(file)
	if err != nil {
		return nil, err
	}
	m := &MMDBIPMatcher{r: r, asn: asn}
	switch r.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		m.kind = mmdbKindASNMaxmind
	case "ipinfo generic_asn_free.mmdb":
		m.kind = mmdbKindASNIPInfo
	default:
		return nil, fmt.Errorf("unsupported asn database type %q in %s", r.Metadata.DatabaseType, file)
	}
	return m, nil
}

func (m *MMDBIPMatcher) Match(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch m.kind {
	case mmdbKindCountry, mmdbKindCountrySing, mmdbKindCountryMetaV0:
		res := m.r.Lookup(addr)
		if !res.Found() {
			return false
		}
		key := mmdbOffsetKey{r: m.r, offset: res.Offset()}
		if cached, ok := mmdbRecordCache.Load(key); ok {
			return matchCachedCountry(cached, m.code)
		}
		cached, ok := decodeCountryRecord(res, m.kind)
		if !ok {
			return false
		}
		mmdbRecordCache.Store(key, cached)
		return matchCachedCountry(cached, m.code)
	case mmdbKindASNMaxmind, mmdbKindASNIPInfo:
		asn, ok := m.LookupASN(addr)
		return ok && asn == m.asn
	}
	return false
}

// LookupASN resolves the autonomous system number of addr in an ASN database.
func (m *MMDBIPMatcher) LookupASN(addr netip.Addr) (uint32, bool) {
	if m == nil || (m.kind != mmdbKindASNMaxmind && m.kind != mmdbKindASNIPInfo) {
		return 0, false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	res := m.r.Lookup(addr)
	if !res.Found() {
		return 0, false
	}
	switch m.kind {
	case mmdbKindASNMaxmind:
		var rec mmdbASNRecord
		if res.Decode(&rec) != nil {
			return 0, false
		}
		return rec.ASN, true
	case mmdbKindASNIPInfo:
		var rec mmdbIPInfoASNRecord
		if res.Decode(&rec) != nil {
			return 0, false
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(rec.ASN, "AS"), 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(asn), true
	default:
		return 0, false
	}
}

// SameReader reports whether m and other query the same underlying MMDB reader.
func (m *MMDBIPMatcher) SameReader(other *MMDBIPMatcher) bool {
	return m != nil && other != nil && m.r == other.r && m.kind == other.kind
}

func decodeCountryRecord(res maxminddb.Result, kind int) (any, bool) {
	switch kind {
	case mmdbKindCountry:
		var rec mmdbCountryRecord
		if res.Decode(&rec) != nil {
			return nil, false
		}
		return strings.ToLower(rec.Country.IsoCode), true
	case mmdbKindCountrySing:
		var code string
		if res.Decode(&code) != nil {
			return nil, false
		}
		return strings.ToLower(code), true
	case mmdbKindCountryMetaV0:
		var v any
		if res.Decode(&v) != nil {
			return nil, false
		}
		switch code := v.(type) {
		case string:
			return strings.ToLower(code), true
		case []any:
			codes := make([]string, 0, len(code))
			for _, e := range code {
				if s, ok := e.(string); ok {
					codes = append(codes, strings.ToLower(s))
				}
			}
			return codes, true
		default:
			return "", true
		}
	default:
		return nil, false
	}
}

func matchCachedCountry(cached any, want string) bool {
	switch v := cached.(type) {
	case string:
		return v == want
	case []string:
		return slices.Contains(v, want)
	default:
		return false
	}
}
