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

// The wire format scanning below (seek, siteDecoder and the field consuming
// helpers) is derived from xray-core's common/geodata/geodat_loader.go,
// Copyright (c) Xray Project, MPL-2.0, adapted for this project.

package geodata

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

const decoderBufSize = 64 * 1024

var errInvalidUTF8 = errors.New("string field contains invalid UTF-8")

// seek advances br to the body of the GeoSite/GeoIP entry for code and returns
// the body length. The dat file is a sequence of [tag 0x0a][varint length][entry
// body]; since protobuf serializes fields in order, the entry body starts with
// the code field (field 1, wire type 2), i.e. [0x0a][varint len(code)][code], which
// allows matching an entry by peeking a few bytes without decoding its body.
func seek(br *bufio.Reader, code []byte, size int64) (int, error) {
	codeL := len(code)
	if codeL == 0 {
		return 0, errors.New("empty code")
	}
	codeHeader := protowire.AppendTag(nil, 1, protowire.BytesType)
	codeHeader = protowire.AppendVarint(codeHeader, uint64(codeL))
	need := len(codeHeader) + codeL

	for {
		tag, err := br.ReadByte()
		if err != nil {
			return 0, err
		}

		x, err := decodeVarint(br)
		if err != nil {
			return 0, err
		}
		if x == 0 || x > uint64(size) || x > uint64(^uint(0)>>1) {
			return 0, fmt.Errorf("invalid body length %d", x)
		}
		bodyL := int(x)

		prefix, err := br.Peek(min(bodyL, need, br.Size()))
		if err != nil {
			if errors.Is(err, io.EOF) && len(prefix) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if tag == 0x0a && bodyL >= need && len(prefix) >= need &&
			bytes.Equal(prefix[:len(codeHeader)], codeHeader) && bytes.EqualFold(prefix[len(codeHeader):need], code) {
			return bodyL, nil
		}
		if _, err := br.Discard(bodyL); err != nil {
			return 0, err
		}
	}
}

func decodeVarint(br *bufio.Reader) (uint64, error) {
	var x uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if shift == 63 && b > 1 {
			break // only one value bit fits in the tenth byte
		}
		x |= (uint64(b) & 0x7F) << shift
		if (b & 0x80) == 0 {
			return x, nil
		}
	}
	return 0, errors.New("varint overflow")
}

type siteDecoder struct {
	want []string
	has  []bool
	fn   func(t DomainType, value string) error
}

func newSiteDecoder(attrs []string, fn func(t DomainType, value string) error) *siteDecoder {
	d := &siteDecoder{fn: fn}
	if len(attrs) > 0 {
		d.want = attrs
		d.has = make([]bool, len(attrs))
	}
	return d
}

// decode walks the fields at the start of b, a part of an encoded GeoSite entry
// body, calls fn for every domain entry that has all the attrs and returns how
// many bytes it used. A field cut off by the end of b is not an error if more
// is set.
func (d *siteDecoder) decode(b []byte, more bool) (int, error) {
	used := 0
	for used < len(b) {
		f, n, err := consumeField(b[used:])
		if errors.Is(err, io.ErrUnexpectedEOF) && more {
			break
		}
		if err != nil {
			return used, err
		}
		used += n
		if f.typ != protowire.BytesType {
			continue
		}
		switch f.num {
		case 1: // code
			if !utf8.Valid(f.v) {
				return used, errInvalidUTF8
			}
		case 2: // domain
			t, value, err := decodeDomain(f.v, d.want, d.has)
			if err != nil {
				return used, err
			}
			if !slices.Contains(d.has, false) {
				if err := d.fn(t, string(value)); err != nil {
					return used, err
				}
			}
		}
	}
	return used, nil
}

// decodeDomain decodes an encoded Domain entry and sets has[i] if one of its
// attributes has the key want[i].
func decodeDomain(b []byte, want []string, has []bool) (t DomainType, value []byte, err error) {
	clear(has)
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return 0, nil, err
		}
		b = b[n:]
		switch {
		case f.num == 1 && f.typ == protowire.VarintType: // type
			t = DomainType(f.x)
		case f.num == 2 && f.typ == protowire.BytesType: // value
			if !utf8.Valid(f.v) {
				return 0, nil, errInvalidUTF8
			}
			value = f.v
		case f.num == 3 && f.typ == protowire.BytesType: // attribute
			key, err := decodeAttributeKey(f.v)
			if err != nil {
				return 0, nil, err
			}
			for i, w := range want {
				if string(key) == w {
					has[i] = true
				}
			}
		}
	}
	return t, value, nil
}

// decodeAttributeKey returns the key of an encoded Domain.Attribute.
func decodeAttributeKey(b []byte) ([]byte, error) {
	var key []byte
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if f.num == 1 && f.typ == protowire.BytesType {
			if !utf8.Valid(f.v) {
				return nil, errInvalidUTF8
			}
			key = f.v
		}
	}
	return key, nil
}

// decodeGeoIP decodes an encoded GeoIP entry body and returns its cidr list.
// The code (field 1) and reverse_match (field 3) fields are ignored.
func decodeGeoIP(b []byte) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if f.num == 2 && f.typ == protowire.BytesType { // cidr
			p, err := decodeCIDR(f.v)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, p)
		}
	}
	return prefixes, nil
}

// decodeCIDR decodes an encoded CIDR. Its ip is a 4 or 16 byte address.
func decodeCIDR(b []byte) (netip.Prefix, error) {
	var ip []byte
	var prefix uint64
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return netip.Prefix{}, err
		}
		b = b[n:]
		switch {
		case f.num == 1 && f.typ == protowire.BytesType: // ip
			ip = f.v
		case f.num == 2 && f.typ == protowire.VarintType: // prefix
			prefix = f.x
		}
	}

	var addr netip.Addr
	switch len(ip) {
	case 4:
		addr = netip.AddrFrom4([4]byte(ip))
	case 16:
		addr = netip.AddrFrom16([16]byte(ip))
	default:
		return netip.Prefix{}, fmt.Errorf("invalid cidr ip length %d", len(ip))
	}
	if prefix > uint64(addr.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("cidr prefix %d exceeds %d", prefix, addr.BitLen())
	}
	return netip.PrefixFrom(addr, int(prefix)), nil
}

type protoField struct {
	num protowire.Number
	typ protowire.Type
	v   []byte // payload of a length-delimited field
	x   uint64 // value of a varint field
}

// consumeField parses the first field of an encoded message and returns it with
// its length.
func consumeField(b []byte) (protoField, int, error) {
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 {
		return protoField{}, 0, protowire.ParseError(n)
	}
	if num > protowire.MaxValidNumber {
		return protoField{}, 0, fmt.Errorf("invalid field number %d", num)
	}
	f := protoField{num: num, typ: typ}
	var m int
	switch typ {
	case protowire.BytesType:
		f.v, m = protowire.ConsumeBytes(b[n:])
	case protowire.VarintType:
		f.x, m = protowire.ConsumeVarint(b[n:])
	default:
		m = protowire.ConsumeFieldValue(num, typ, b[n:])
	}
	if m < 0 {
		return protoField{}, 0, protowire.ParseError(m)
	}
	return f, n + m, nil
}
