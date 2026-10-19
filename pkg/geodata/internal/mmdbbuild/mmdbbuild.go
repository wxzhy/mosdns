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

// Package mmdbbuild writes minimal MaxMind DB files, for tests. It follows
// the MaxMind DB file format spec: a binary search tree, a 16 byte null
// separator, the data section, and a metadata section starting with the
// "\xab\xcd\xefMaxMind.com" marker. Only record size 24 is supported, which
// caps node counts and data pointers at 2^24-1, enough for test databases.
package mmdbbuild

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Wire data types, see the MaxMind DB spec. Types above 7 are encoded as
// "extended": wire type 0 in the control byte, followed by a byte holding
// the actual type minus 7.
const (
	wireString = 2
	wireUint16 = 5
	wireUint32 = 6
	wireMap    = 7
	wireUint64 = 9
	wireArray  = 11
	recordSize = 24
)

// Field is a map entry.
type Field struct {
	Key   string
	Value []byte
}

func F(key string, value []byte) Field {
	return Field{Key: key, Value: value}
}

// String encodes an utf-8 string value.
func String(s string) []byte {
	return appendSize(nil, wireString, len(s), []byte(s))
}

// Uint32 encodes a 32 bit unsigned integer value.
func Uint32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return appendSize(nil, wireUint32, len(b), b[:])
}

// Map encodes a map value.
func Map(fields ...Field) []byte {
	var payload []byte
	for _, f := range fields {
		payload = append(payload, String(f.Key)...)
		payload = append(payload, f.Value...)
	}
	return appendSize(nil, wireMap, len(fields), payload)
}

// Array encodes an array value.
func Array(items ...[]byte) []byte {
	var payload []byte
	for _, item := range items {
		payload = append(payload, item...)
	}
	return appendSize(nil, 0, len(items), payload, byte(wireArray-7))
}

// appendSize appends a type-length-value. Sizes up to 28 go into the
// control byte's low 5 bits; larger ones use the extended size forms: size
// field 29/30/31 followed by 1/2/3 big-endian bytes holding size minus
// 29/285/65821 respectively. extra is written right after the control/size
// bytes, before the payload (used for extended types).
func appendSize(b []byte, typ, size int, payload []byte, extra ...byte) []byte {
	switch {
	case size < 29:
		b = append(b, byte(typ)<<5|byte(size))
	case size <= 284:
		b = append(b, byte(typ)<<5|29, byte(size-29))
	case size <= 65820:
		v := size - 285
		b = append(b, byte(typ)<<5|30, byte(v>>8), byte(v))
	default:
		v := size - 65821
		b = append(b, byte(typ)<<5|31, byte(v>>16), byte(v>>8), byte(v))
	}
	b = append(b, extra...)
	return append(b, payload...)
}

type treeNode struct {
	child [2]*treeNode
	data  int // index into Writer.records, -1 if this node has no data
}

// Writer accumulates prefixes and their encoded records, and serializes
// them into a mmdb file.
type Writer struct {
	databaseType string
	ipVersion    uint16

	root      *treeNode
	records   [][]byte
	nodeCount uint32
}

// New returns a Writer for a database with the given database_type
// metadata. ipVersion must be 4 or 6. For an ip_version 6 database, ipv4
// prefixes are stored on the ::ffff:0:0/96 mapped path, the MaxMind
// convention, so that ipv4 lookups work.
func New(databaseType string, ipVersion uint16) *Writer {
	return &Writer{
		databaseType: databaseType,
		ipVersion:    ipVersion,
		root:         &treeNode{data: -1},
	}
}

// Add maps prefix to the encoded record.
func (w *Writer) Add(prefix netip.Prefix, record []byte) error {
	prefix = prefix.Masked()
	addr := prefix.Addr()

	// In an ip_version 6 database an ipv4 prefix lives on the all-zero
	// ::/96 path: readers enter the ipv4 subtree by traversing 96 zero
	// bits from the root, then the ipv4 address bits.
	var bits [16]byte
	bitLen := prefix.Bits()
	if addr.Is4() {
		a4 := addr.As4()
		if w.ipVersion == 6 {
			copy(bits[12:], a4[:])
		} else {
			copy(bits[0:], a4[:])
		}
	} else {
		if w.ipVersion == 4 {
			return fmt.Errorf("ipv6 prefix %s in an ip_version 4 database", prefix)
		}
		bits = addr.As16()
	}

	idx := len(w.records)
	w.records = append(w.records, record)

	skip := 0
	if addr.Is4() && w.ipVersion == 6 {
		skip = 96
	}
	n := w.root
	for i := 0; i < skip+bitLen; i++ {
		bit := (bits[i/8] >> (7 - uint(i)%8)) & 1
		if n.child[bit] == nil {
			n.child[bit] = &treeNode{data: -1}
		}
		n = n.child[bit]
	}
	n.data = idx
	return nil
}

// Bytes serializes the database.
func (w *Writer) Bytes() ([]byte, error) {
	// Flatten the tree: assign node indexes depth-first from the root.
	indexes := make(map[*treeNode]uint32)
	var assign func(n *treeNode)
	assign = func(n *treeNode) {
		indexes[n] = w.nodeCount
		w.nodeCount++
		for _, c := range n.child {
			if c != nil {
				assign(c)
			}
		}
	}
	assign(w.root)
	if w.nodeCount >= 1<<recordSize {
		return nil, fmt.Errorf("too many nodes: %d", w.nodeCount)
	}

	// Data section. A record's tree pointer value is its data section
	// offset plus node_count plus the 16 byte separator.
	var dataSection []byte
	offsets := make([]int, len(w.records))
	for i, r := range w.records {
		offsets[i] = len(dataSection)
		dataSection = append(dataSection, r...)
	}
	dataPtr := func(recordIdx int) (uint32, error) {
		v := uint64(offsets[recordIdx]) + uint64(w.nodeCount) + 16
		if v >= 1<<recordSize {
			return 0, fmt.Errorf("data pointer overflow")
		}
		return uint32(v), nil
	}

	// Search tree: record size 24 -> 6 bytes per node, two 3-byte
	// big-endian records. A record pointing nowhere (miss) holds
	// node_count.
	tree := make([]byte, 0, int(w.nodeCount)*6)
	var emit func(n *treeNode, inherited int) error
	emit = func(n *treeNode, inherited int) error {
		effective := inherited
		if n.data >= 0 {
			effective = n.data
		}
		for _, c := range n.child {
			var v uint32
			switch {
			case c != nil:
				v = indexes[c]
			case effective >= 0:
				p, err := dataPtr(effective)
				if err != nil {
					return err
				}
				v = p
			default:
				v = w.nodeCount // miss
			}
			tree = append(tree, byte(v>>16), byte(v>>8), byte(v))
		}
		for _, c := range n.child {
			if c != nil {
				if err := emit(c, effective); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := emit(w.root, -1); err != nil {
		return nil, err
	}

	metadata := Map(
		F("node_count", Uint32(w.nodeCount)),
		F("record_size", uint16Value(recordSize)),
		F("ip_version", uint16Value(int(w.ipVersion))),
		F("database_type", String(w.databaseType)),
		F("binary_format_major_version", uint16Value(2)),
		F("binary_format_minor_version", uint16Value(0)),
		F("build_epoch", uint64Value(0)),
	)

	file := make([]byte, 0, len(tree)+16+len(dataSection)+len(metadata)+14)
	file = append(file, tree...)
	file = append(file, make([]byte, 16)...) // data section separator
	file = append(file, dataSection...)
	file = append(file, 0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm')
	file = append(file, metadata...)
	return file, nil
}

func uint16Value(v int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	return appendSize(nil, wireUint16, len(b), b[:])
}

func uint64Value(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return appendSize(nil, 0, len(b), b[:], byte(wireUint64-7))
}
