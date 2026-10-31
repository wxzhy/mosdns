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
	"bytes"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"os"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

const PluginType = "domain_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewDomainSet(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	// Exps are domain expressions. Besides the plain "type:pattern" syntax,
	// *ray geosite expressions are supported: geosite:CODE (loads CODE from
	// the instance's geodata.geosite, or geosite.dat in the working directory),
	// ext:FILE:CODE[@attr...] (loads
	// CODE from FILE, attrs have AND semantics). ext-domain: and ext-site:
	// are aliases of ext:.
	Exps  []string `yaml:"exps"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	mg atomic.Pointer[MatcherGroup]
	fw *utils.FileWatcher
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return d
}

func (d *DomainSet) Match(s string) (struct{}, bool) {
	if m := d.mg.Load(); m != nil {
		return m.Match(s)
	}
	return struct{}{}, false
}

func (d *DomainSet) Close() error { return d.fw.Close() }

// NewDomainSet inits a DomainSet from given args.
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{}
	var paths geodata.Paths
	if bp != nil {
		paths = bp.M().GeodataPaths()
	}
	load := func() (*MatcherGroup, error) {
		loader := NewMixLoader(paths)
		if err := loader.LoadExpsAndFiles(args.Exps, args.Files); err != nil {
			return nil, err
		}
		mg := MatcherGroup(loader.Matchers())
		for _, tag := range args.Sets {
			if bp == nil {
				return nil, fmt.Errorf("missing plugin context for set %s", tag)
			}
			provider, ok := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
			if !ok {
				return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
			}
			mg = append(mg, provider.GetDomainMatcher())
		}
		return &mg, nil
	}
	initial := utils.SnapshotFileStates(args.Files)
	mg, err := load()
	if err != nil {
		return nil, err
	}
	ds.mg.Store(mg)
	if len(args.Files) > 0 {
		logger := zap.NewNop()
		if bp != nil {
			logger = bp.L()
		}
		ds.fw = utils.StartFileWatcherFromSnapshot(args.Files, initial, 3*time.Second, func(changed []string) bool {
			m, err := load()
			if err != nil {
				logger.Error("failed to reload domain_set", zap.Error(err))
				return false
			}
			ds.mg.Store(m)
			logger.Info("reloaded domain_set", zap.Strings("files", changed))
			return true
		})
	}
	return ds, nil
}

// MixLoader loads plain domain expressions and files into a private matcher,
// and geosite expressions into shared, cached matchers.
type MixLoader struct {
	own    *domain.MixMatcher[struct{}]
	shared []domain.Matcher[struct{}]
	paths  geodata.Paths
}

func NewMixLoader(paths ...geodata.Paths) *MixLoader {
	l := &MixLoader{own: domain.NewDomainMixMatcher()}
	if len(paths) > 0 {
		l.paths = paths[0]
	}
	return l
}

func (l *MixLoader) LoadExpsAndFiles(exps []string, fs []string) error {
	if err := l.LoadExps(exps); err != nil {
		return err
	}
	return l.LoadFiles(fs)
}

func (l *MixLoader) LoadExps(exps []string) error {
	for i, exp := range exps {
		if err := l.loadExp(exp); err != nil {
			return fmt.Errorf("failed to load expression #%d %s, %w", i, exp, err)
		}
	}
	return nil
}

// loadExp adds exp. exp can either be a plain domain expression accepted by
// domain.MixMatcher, or an *ray style geosite expression referring to an
// entry in a geosite dat file (see geodata.ParseDomainExp), which is loaded
// as a shared matcher.
func (l *MixLoader) loadExp(exp string) error {
	file, code, attrs, ok, err := l.paths.ParseDomainExp(exp)
	if err != nil {
		return err
	}
	if ok {
		m, err := geodata.GetSiteMatcher(file, code, attrs)
		if err != nil {
			return err
		}
		if !containsMatcher(l.shared, m) {
			l.shared = append(l.shared, m)
		}
		return nil
	}
	return l.own.Add(exp, struct{}{})
}

func containsMatcher(ms []domain.Matcher[struct{}], m domain.Matcher[struct{}]) bool {
	for _, e := range ms {
		if e == m {
			return true
		}
	}
	return false
}

func (l *MixLoader) LoadFiles(fs []string) error {
	for i, f := range fs {
		if err := LoadFile(f, l.own); err != nil {
			return fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
	}
	return nil
}

func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	if len(f) > 0 {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		if err := domain.LoadFromTextReader[struct{}](m, bytes.NewReader(b), nil); err != nil {
			return err
		}
	}
	return nil
}

// Matchers returns the loaded matchers, shared geosite matchers first.
func (l *MixLoader) Matchers() []domain.Matcher[struct{}] {
	var ms []domain.Matcher[struct{}]
	ms = append(ms, l.shared...)
	if l.own.Len() > 0 {
		ms = append(ms, l.own)
	}
	return ms
}
