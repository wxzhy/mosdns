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
	// geosite.dat in the working directory), ext:FILE:CODE[@attr...] (loads
	// CODE from FILE, attrs have AND semantics). ext-domain: and ext-site:
	// are aliases of ext:.
	Exps  []string `yaml:"exps"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	mg []domain.Matcher[struct{}]
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return MatcherGroup(d.mg)
}

// NewDomainSet inits a DomainSet from given args.
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{}

	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles(args.Exps, args.Files, m); err != nil {
		return nil, err
	}
	if m.Len() > 0 {
		ds.mg = append(ds.mg, m)
	}

	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		m := provider.GetDomainMatcher()
		ds.mg = append(ds.mg, m)
	}
	return ds, nil
}

func LoadExpsAndFiles(exps []string, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	if err := LoadFiles(fs, m); err != nil {
		return err
	}
	return nil
}

func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := loadExp(exp, m); err != nil {
			return fmt.Errorf("failed to load expression #%d %s, %w", i, exp, err)
		}
	}
	return nil
}

// loadExp adds exp to m. exp can either be a plain domain expression accepted
// by domain.MixMatcher, or an *ray style geosite expression referring to an
// entry in a geosite dat file, i.e. geosite:CODE, ext:FILE:CODE[@attr...],
// ext-domain: and ext-site: (see geodata.ParseDomainExp). geosite.dat is
// looked up in the working directory unless the ext syntax gives a path.
func loadExp(exp string, m *domain.MixMatcher[struct{}]) error {
	file, code, attrs, ok, err := geodata.ParseDomainExp(exp)
	if err != nil {
		return err
	}
	if ok {
		return geodata.LoadSite(file, code, attrs, func(t geodata.DomainType, value string) error {
			typ, err := matcherTypePrefix(t)
			if err != nil {
				return err
			}
			return m.Add(typ+":"+value, struct{}{})
		})
	}
	return m.Add(exp, struct{}{})
}

// matcherTypePrefix maps a geosite domain rule type to the domain.MixMatcher
// type prefix of the matcher with the same semantics.
func matcherTypePrefix(t geodata.DomainType) (string, error) {
	switch t {
	case geodata.TypeFull:
		return domain.MatcherFull, nil
	case geodata.TypeDomain:
		return domain.MatcherDomain, nil
	case geodata.TypeRegex:
		return domain.MatcherRegexp, nil
	case geodata.TypeSubstr:
		return domain.MatcherKeyword, nil
	default:
		return "", fmt.Errorf("unknown geodata domain type %d", t)
	}
}

func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
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
