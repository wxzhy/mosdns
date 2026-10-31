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
	"bytes"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

const PluginType = "ip_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewIPSet(bp, args.(*Args))
}

type Args struct {
	// IPs are ip/prefix strings. Besides plain ips and CIDRs, *ray style
	// expressions are supported: geoip:CODE (loads CODE from geodata.geoip,
	// or the first
	// existing of geoip.dat, geoip.metadb, Country.mmdb, geoip.mmdb in the
	// working directory; dat and maxmind formats are auto-detected),
	// asn:AS_NUMBER (maxmind asn db, tried among ASN.mmdb, GeoLite2-ASN.mmdb,
	// asn.mmdb unless geodata.asn is configured; AS_NUMBER is digits with
	// an optional "AS" prefix), and
	// ext:FILE:CODE (auto-detects the format from the file content). ext-ip:
	// is an alias of ext:.
	IPs   []string `yaml:"ips"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.IPMatcherProvider = (*IPSet)(nil)

type IPSet struct {
	mg atomic.Pointer[MatcherGroup]
	fw *utils.FileWatcher
}

func (d *IPSet) GetIPMatcher() netlist.Matcher {
	return d
}

func (d *IPSet) Match(ip netip.Addr) bool {
	if m := d.mg.Load(); m != nil {
		return m.Match(ip)
	}
	return false
}
func (d *IPSet) Close() error { return d.fw.Close() }

func NewIPSet(bp *coremain.BP, args *Args) (*IPSet, error) {
	p := &IPSet{}
	var paths geodata.Paths
	if bp != nil {
		paths = bp.M().GeodataPaths()
	}
	load := func() (*MatcherGroup, error) {
		loader := NewListLoader(paths)
		if err := loader.LoadFromIPsAndFiles(args.IPs, args.Files); err != nil {
			return nil, err
		}
		mg := MatcherGroup(loader.Matchers())
		for _, tag := range args.Sets {
			if bp == nil {
				return nil, fmt.Errorf("missing plugin context for set %s", tag)
			}
			provider, ok := bp.M().GetPlugin(tag).(data_provider.IPMatcherProvider)
			if !ok {
				return nil, fmt.Errorf("%s is not an IPMatcherProvider", tag)
			}
			mg = append(mg, provider.GetIPMatcher())
		}
		return &mg, nil
	}
	initial := utils.SnapshotFileStates(args.Files)
	mg, err := load()
	if err != nil {
		return nil, err
	}
	p.mg.Store(mg)
	if len(args.Files) > 0 {
		logger := zap.NewNop()
		if bp != nil {
			logger = bp.L()
		}
		p.fw = utils.StartFileWatcherFromSnapshot(args.Files, initial, 3*time.Second, func(changed []string) bool {
			m, err := load()
			if err != nil {
				logger.Error("failed to reload ip_set", zap.Error(err))
				return false
			}
			p.mg.Store(m)
			logger.Info("reloaded ip_set", zap.Strings("files", changed))
			return true
		})
	}
	return p, nil
}

func parseNetipPrefix(s string) (netip.Prefix, error) {
	if strings.ContainsRune(s, '/') {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

// ListLoader loads plain ips and files into a private list, and geoip/asn
// expressions into shared, cached matchers.
type ListLoader struct {
	own    *netlist.List
	shared []netlist.Matcher
	paths  geodata.Paths
}

func NewListLoader(paths ...geodata.Paths) *ListLoader {
	l := &ListLoader{own: netlist.NewList()}
	if len(paths) > 0 {
		l.paths = paths[0]
	}
	return l
}

func (l *ListLoader) LoadFromIPsAndFiles(ips []string, fs []string) error {
	if err := l.LoadFromIPs(ips); err != nil {
		return err
	}
	return l.LoadFromFiles(fs)
}

func (l *ListLoader) LoadFromIPs(ips []string) error {
	for i, s := range ips {
		if err := l.loadIP(s); err != nil {
			return fmt.Errorf("invalid ip #%d %s, %w", i, s, err)
		}
	}
	return nil
}

// loadIP appends s. s can either be a plain ip/prefix, or an ip expression
// referring to a geoip entry or an as number (see geodata.ParseIPExp),
// which is loaded as a shared matcher.
func (l *ListLoader) loadIP(s string) error {
	file, kind, code, ok, err := l.paths.ParseIPExp(s)
	if err != nil {
		return err
	}
	if ok {
		var m netlist.Matcher
		if kind == geodata.IPExpASN {
			m, err = geodata.GetASNMatcher(file, code)
		} else {
			m, err = geodata.GetGeoIPMatcher(file, code)
		}
		if err != nil {
			return err
		}
		if !containsMatcher(l.shared, m) {
			l.shared = append(l.shared, m)
		}
		return nil
	}
	p, err := parseNetipPrefix(s)
	if err != nil {
		return err
	}
	l.own.Append(p)
	return nil
}

func containsMatcher(ms []netlist.Matcher, m netlist.Matcher) bool {
	for _, e := range ms {
		if e == m {
			return true
		}
	}
	return false
}

func (l *ListLoader) LoadFromFiles(fs []string) error {
	for i, f := range fs {
		if err := LoadFromFile(f, l.own); err != nil {
			return fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
	}
	return nil
}

func LoadFromFile(f string, l *netlist.List) error {
	if len(f) > 0 {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := netlist.LoadFromReader(l, bytes.NewReader(b)); err != nil {
			return err
		}
	}
	return nil
}

// Matchers returns the loaded matchers, shared geoip/asn matchers first.
func (l *ListLoader) Matchers() []netlist.Matcher {
	l.own.Sort()
	var ms []netlist.Matcher
	ms = append(ms, l.shared...)
	if l.own.Len() > 0 {
		ms = append(ms, l.own)
	}
	return ms
}

type MatcherGroup []netlist.Matcher

func (mg MatcherGroup) Match(addr netip.Addr) bool {
	for _, m := range mg {
		if m.Match(addr) {
			return true
		}
	}
	return false
}
