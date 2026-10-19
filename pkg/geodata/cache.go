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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
)

// Default file candidates for the geoip:/asn: shortcuts, resolved in the
// working directory, first existing file wins. Both dat and maxmind formats
// are accepted for geoip; asn only comes as a maxmind database.
var (
	geoIPDefaultFiles = []string{"geoip.dat", "geoip.metadb", "Country.mmdb", "geoip.mmdb"}
	asnDefaultFiles   = []string{"ASN.mmdb", "GeoLite2-ASN.mmdb", "asn.mmdb"}
)

// Shared, immutable matchers, keyed by file/code(/attrs). Loading the same
// entry in multiple places (different plugins, anonymous matcher exps)
// reuses one matcher instance instead of building a duplicate one.
var (
	siteMatcherCache sync.Map // key -> *domain.MixMatcher[struct{}]
	ipMatcherCache   sync.Map // key -> netlist.Matcher
)

func cacheKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

// GetSiteMatcher returns a shared, immutable matcher for the geosite entry of
// code in the dat file. The returned matcher must not be modified.
func GetSiteMatcher(file, code string, attrs []string) (*domain.MixMatcher[struct{}], error) {
	file = absPath(file)
	sortedAttrs := slices.Clone(attrs)
	sort.Strings(sortedAttrs)
	key := cacheKey("site", file, strings.ToUpper(code), strings.Join(sortedAttrs, ","))
	if v, ok := siteMatcherCache.Load(key); ok {
		return v.(*domain.MixMatcher[struct{}]), nil
	}
	m, err := buildSiteMatcher(file, code, attrs)
	if err != nil {
		return nil, err
	}
	actual, _ := siteMatcherCache.LoadOrStore(key, m)
	return actual.(*domain.MixMatcher[struct{}]), nil
}

func buildSiteMatcher(file, code string, attrs []string) (*domain.MixMatcher[struct{}], error) {
	m := domain.NewDomainMixMatcher()
	if err := LoadSite(file, code, attrs, func(t DomainType, value string) error {
		typ, err := matcherTypePrefix(t)
		if err != nil {
			return err
		}
		return m.Add(typ+":"+value, struct{}{})
	}); err != nil {
		return nil, err
	}
	return m, nil
}

// matcherTypePrefix maps a geosite domain rule type to the domain.MixMatcher
// type prefix of the matcher with the same semantics.
func matcherTypePrefix(t DomainType) (string, error) {
	switch t {
	case TypeFull:
		return domain.MatcherFull, nil
	case TypeDomain:
		return domain.MatcherDomain, nil
	case TypeRegex:
		return domain.MatcherRegexp, nil
	case TypeSubstr:
		return domain.MatcherKeyword, nil
	default:
		return "", fmt.Errorf("unknown geodata domain type %d", t)
	}
}

// GetGeoIPMatcher returns a shared, immutable matcher for the geoip entry of
// code. The file format, dat or maxmind database, is auto-detected by the
// file content; a maxmind file holding asn records requires code to be an as
// number. If file is empty, the default geoip file candidates are tried in
// the working directory.
func GetGeoIPMatcher(file, code string) (netlist.Matcher, error) {
	if file == "" {
		f, err := resolveDefaultFile(geoIPDefaultFiles, "geoip")
		if err != nil {
			return nil, err
		}
		file = f
	}
	file = absPath(file)
	key := cacheKey("ip", file, strings.ToUpper(code))
	if v, ok := ipMatcherCache.Load(key); ok {
		return v.(netlist.Matcher), nil
	}
	m, err := buildGeoIPMatcher(file, code)
	if err != nil {
		return nil, err
	}
	actual, _ := ipMatcherCache.LoadOrStore(key, m)
	return actual.(netlist.Matcher), nil
}

func buildGeoIPMatcher(file, code string) (netlist.Matcher, error) {
	if isMMDBFile(file) {
		r, err := openMMDB(file)
		if err != nil {
			return nil, err
		}
		if mmdbIsASNDB(r) {
			asn, err := parseASNCode(code)
			if err != nil {
				return nil, fmt.Errorf("%s is an asn database, the code must be an as number: %w", file, err)
			}
			return newMMDBASNMatcher(file, asn)
		}
		return newMMDBCountryMatcher(file, code)
	}

	prefixes, err := LoadIP(file, code)
	if err != nil {
		return nil, err
	}
	l := netlist.NewList()
	l.Append(prefixes...)
	l.Sort()
	return l, nil
}

// GetASNMatcher returns a shared, immutable matcher matching the addresses of
// the given as number. code is digits with an optional "AS" prefix. If file
// is empty, the default asn file candidates are tried in the working
// directory. The file must be a maxmind asn database.
func GetASNMatcher(file, code string) (netlist.Matcher, error) {
	asn, err := parseASNCode(code)
	if err != nil {
		return nil, err
	}
	if file == "" {
		f, err := resolveDefaultFile(asnDefaultFiles, "asn")
		if err != nil {
			return nil, err
		}
		file = f
	}
	file = absPath(file)
	key := cacheKey("ip", file, fmt.Sprint(asn))
	if v, ok := ipMatcherCache.Load(key); ok {
		return v.(netlist.Matcher), nil
	}
	m, err := newMMDBASNMatcher(file, asn)
	if err != nil {
		return nil, err
	}
	actual, _ := ipMatcherCache.LoadOrStore(key, m)
	return actual.(netlist.Matcher), nil
}

// resolveDefaultFile returns the first existing file among candidates.
func resolveDefaultFile(candidates []string, what string) (string, error) {
	for _, f := range candidates {
		if st, err := os.Stat(f); err == nil && !st.IsDir() {
			return f, nil
		}
	}
	return "", fmt.Errorf("no %s database found, tried %v in the working directory", what, candidates)
}

func absPath(file string) string {
	abs, err := filepath.Abs(file)
	if err != nil {
		return file
	}
	return abs
}
