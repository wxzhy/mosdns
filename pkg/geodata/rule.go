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
	"strings"
)

const (
	DefaultGeoSiteDat = "geosite.dat"
	DefaultGeoIPDat   = "geoip.dat"
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

// ParseIPExp parses an *ray style ip expression that refers to a geoip entry
// in a dat file:
//
//	geoip:CODE
//	ext:FILE:CODE    (ext-ip: is an alias of ext:)
//
// If s is such an expression, ok is true and file/code describe the entry.
// Otherwise ok is false and s should be treated as a plain ip expression.
//
// The separator between FILE and CODE is the last ':' of the expression, so
// that file paths containing ':' (e.g. windows absolute paths) are accepted.
func ParseIPExp(s string) (file, code string, ok bool, err error) {
	if strings.HasPrefix(s, "!") {
		return "", "", true, errors.New(`reverse match prefix "!" is not supported`)
	}
	var rest string
	switch {
	case strings.HasPrefix(s, "geoip:"):
		rest = DefaultGeoIPDat + ":" + s[len("geoip:"):]
	case strings.HasPrefix(s, "ext:"), strings.HasPrefix(s, "ext-ip:"):
		rest = s[strings.Index(s, ":")+1:]
	default:
		return "", "", false, nil
	}

	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", "", true, errors.New("missing code, expect ext:\"file\":\"code\"")
	}
	file, code = rest[:i], rest[i+1:]
	if file == "" {
		return "", "", true, errors.New("empty file")
	}
	if code == "" {
		return "", "", true, errors.New("empty code")
	}
	if strings.HasPrefix(code, "!") {
		return "", "", true, errors.New(`reverse match prefix "!" is not supported`)
	}
	return file, code, true, nil
}
