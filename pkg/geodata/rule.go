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
	"fmt"
	"strconv"
	"strings"
)

const (
	DefaultGeoSiteDat = "geosite.dat"
	DefaultGeoIPDat   = "geoip.dat"
)

// IPExpKind indicates what an ip expression refers to.
type IPExpKind int

const (
	// IPExpGeoIP refers to a geoip entry, in either a dat or a maxmind
	// database file.
	IPExpGeoIP IPExpKind = iota
	// IPExpASN refers to an autonomous system number in a maxmind asn
	// database.
	IPExpASN
)

// ParseDomainExp parses an *ray style domain expression that refers to a
// geosite entry in a dat file:
//
//	geosite:CODE
//	ext:FILE:CODE[@attr1@attr2]    (ext-domain: and ext-site: are aliases of ext:)
//
// If s is such an expression, ok is true and file/code/attrs describe the
// entry. Otherwise ok is false and s should be treated as a plain domain
// expression.
//
// The separator between FILE and CODE is the last ':' of the expression, so
// that file paths containing ':' (e.g. windows absolute paths) are accepted.
// Multiple attrs have AND semantics, as in xray.
func ParseDomainExp(s string) (file, code string, attrs []string, ok bool, err error) {
	if strings.HasPrefix(s, "!") {
		return "", "", nil, true, errors.New(`reverse match prefix "!" is not supported`)
	}
	var rest string
	switch {
	case strings.HasPrefix(s, "geosite:"):
		rest = DefaultGeoSiteDat + ":" + s[len("geosite:"):]
	case strings.HasPrefix(s, "ext:"),
		strings.HasPrefix(s, "ext-domain:"),
		strings.HasPrefix(s, "ext-site:"):
		rest = s[strings.Index(s, ":")+1:]
	default:
		return "", "", nil, false, nil
	}

	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", "", nil, true, errors.New("missing code, expect ext:\"file\":\"code\"")
	}
	file, codeWithAttrs := rest[:i], rest[i+1:]
	if file == "" {
		return "", "", nil, true, errors.New("empty file")
	}
	if strings.HasSuffix(codeWithAttrs, "@") || strings.Contains(codeWithAttrs, "@@") {
		return "", "", nil, true, errors.New("empty attr")
	}
	code, attrsStr, _ := strings.Cut(codeWithAttrs, "@")
	if code == "" {
		return "", "", nil, true, errors.New("empty code")
	}
	if attrsStr != "" {
		for _, attr := range strings.Split(attrsStr, "@") {
			attrs = append(attrs, strings.ToLower(attr))
		}
	}
	return file, code, attrs, true, nil
}

// ParseIPExp parses an ip expression that refers to a geoip entry or an
// autonomous system number:
//
//	geoip:CODE                     (dat or maxmind db, resolved among the
//	                                 default geoip file candidates)
//	asn:AS_NUMBER                  (maxmind asn db, resolved among the
//	                                 default asn file candidates)
//	ext:FILE:CODE                  (dat or maxmind db, auto-detected by the
//	                                 file content; for an asn database CODE
//	                                 must be an as number)
//	ext-ip:FILE:CODE               (alias of ext:)
//
// If s is such an expression, ok is true and file/kind/code describe it.
// file is empty for the default-file shortcuts (geoip:, asn:) and non-empty
// for the ext syntax. AS_NUMBER is digits with an optional "AS" prefix, e.g.
// 13335 or AS13335. Otherwise ok is false and s should be treated as a plain
// ip expression.
//
// The separator between FILE and CODE is the last ':' of the expression, so
// that file paths containing ':' (e.g. windows absolute paths) are accepted.
func ParseIPExp(s string) (file string, kind IPExpKind, code string, ok bool, err error) {
	if strings.HasPrefix(s, "!") {
		return "", 0, "", true, errors.New(`reverse match prefix "!" is not supported`)
	}
	var rest string
	switch {
	case strings.HasPrefix(s, "geoip:"):
		kind, rest = IPExpGeoIP, s[len("geoip:"):]
	case strings.HasPrefix(s, "asn:"):
		kind, rest = IPExpASN, s[len("asn:"):]
	case strings.HasPrefix(s, "ext:"), strings.HasPrefix(s, "ext-ip:"):
		kind = IPExpGeoIP
		rest = s[strings.Index(s, ":")+1:]
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return "", 0, "", true, errors.New("missing code, expect ext:\"file\":\"code\"")
		}
		file, rest = rest[:i], rest[i+1:]
		if file == "" {
			return "", 0, "", true, errors.New("empty file")
		}
	default:
		return "", 0, "", false, nil
	}

	code = rest
	if code == "" {
		return "", 0, "", true, errors.New("empty code")
	}
	if strings.HasPrefix(code, "!") {
		return "", 0, "", true, errors.New(`reverse match prefix "!" is not supported`)
	}
	if kind == IPExpASN {
		if _, perr := parseASNCode(code); perr != nil {
			return "", 0, "", true, fmt.Errorf("invalid asn %q, expect an as number like 13335", code)
		}
	}
	return file, kind, code, true, nil
}

// parseASNCode parses an as number with an optional "AS" prefix.
func parseASNCode(code string) (uint32, error) {
	c := code
	if len(c) > 2 && strings.EqualFold(c[:2], "as") {
		c = c[2:]
	}
	n, err := strconv.ParseUint(c, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid as number %q", code)
	}
	return uint32(n), nil
}
