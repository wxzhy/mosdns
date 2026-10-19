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

// Package geodata loads domain and ip lists from *ray format geosite.dat /
// geoip.dat files, i.e. the protobuf serialized GeoSiteList / GeoIPList
// messages defined by xray-core's geodat.proto.
//
// The dat file is scanned directly on the protobuf wire format instead of being
// unmarshalled into generated messages, so this package requires no generated
// protobuf code. See decode.go.
package geodata

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// DomainType is the rule type of a geosite domain entry. It corresponds to
// Domain.Type in xray-core's geodat.proto.
type DomainType uint8

const (
	// TypeSubstr matches any domain that contains the value as a substring.
	TypeSubstr DomainType = 0
	// TypeRegex matches the value as a regular expression.
	TypeRegex DomainType = 1
	// TypeDomain matches the domain itself and all its subdomains.
	TypeDomain DomainType = 2
	// TypeFull matches the domain exactly.
	TypeFull DomainType = 3
)

// LoadSite calls fn, in file order, with the type and value of every domain
// entry of code in the geosite dat file. If attrs is not empty, only entries
// that have all the attrs are passed to fn. code is compared case-insensitively.
// An error returned by fn aborts the loading.
func LoadSite(file, code string, attrs []string, fn func(t DomainType, value string) error) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", file, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(f, decoderBufSize)
	n, err := seek(br, []byte(strings.ToUpper(code)), st.Size())
	if err != nil {
		return newSeekError(err, file, code)
	}

	d := newSiteDecoder(attrs, fn)
	for n > 0 {
		w, err := br.Peek(min(n, br.Size()))
		if err != nil {
			return unexpectedEOF(err)
		}
		used, err := d.decode(w, len(w) < n)
		if err != nil {
			return fmt.Errorf("failed to decode geosite %s:%s, %w", file, code, err)
		}
		if used == 0 {
			break // a field longer than the buffer, handled below
		}
		br.Discard(used)
		n -= used
	}
	if n > 0 {
		w := make([]byte, n)
		if _, err := io.ReadFull(br, w); err != nil {
			return unexpectedEOF(err)
		}
		if _, err := d.decode(w, false); err != nil {
			return fmt.Errorf("failed to decode geosite %s:%s, %w", file, code, err)
		}
	}
	return nil
}

// LoadIP loads the ip prefixes of code from the geoip dat file. code is
// compared case-insensitively. The reverse_match flag in the dat file is
// ignored.
func LoadIP(file, code string) ([]netip.Prefix, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", file, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(f, decoderBufSize)
	bodyL, err := seek(br, []byte(strings.ToUpper(code)), st.Size())
	if err != nil {
		return nil, newSeekError(err, file, code)
	}

	body := make([]byte, bodyL)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, unexpectedEOF(err)
	}
	prefixes, err := decodeGeoIP(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geoip %s:%s, %w", file, code, err)
	}
	return prefixes, nil
}

func newSeekError(err error, file, code string) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("code %s not found in %s", code, file)
	}
	return fmt.Errorf("failed to load code %s from %s, %w", code, file, err)
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
