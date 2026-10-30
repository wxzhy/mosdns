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

package arbitrary

import (
	"bytes"
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/zone_file"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

const PluginType = "arbitrary"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Rules []string `yaml:"rules"`
	Files []string `yaml:"files"`
}

var _ sequence.Executable = (*Arbitrary)(nil)

type Arbitrary struct {
	m  atomic.Pointer[zone_file.Matcher]
	fw *utils.FileWatcher
}

func NewArbitrary(args *Args) (*Arbitrary, error) {
	return newArbitrary(nil, args, 3*time.Second)
}

func newArbitrary(bp *coremain.BP, args *Args, interval time.Duration) (*Arbitrary, error) {
	if args == nil {
		return nil, fmt.Errorf("arbitrary: missing args")
	}
	rules, files := slices.Clone(args.Rules), slices.Clone(args.Files)
	load := func() (*zone_file.Matcher, error) {
		m := new(zone_file.Matcher)
		for i, s := range rules {
			if err := m.Load(strings.NewReader(s)); err != nil {
				return nil, fmt.Errorf("failed to load rr #%d [%s], %w", i, s, err)
			}
		}
		for i, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file #%d [%s], %w", i, file, err)
			}
			if err := m.Load(bytes.NewReader(b)); err != nil {
				return nil, fmt.Errorf("failed to load rr file #%d [%s], %w", i, file, err)
			}
		}
		return m, nil
	}
	m, err := load()
	if err != nil {
		return nil, err
	}
	a := &Arbitrary{}
	a.m.Store(m)
	if len(files) > 0 {
		logger := zap.NewNop()
		if bp != nil {
			logger = bp.L()
		}
		a.fw = utils.StartFileWatcher(files, interval, func(changed []string) {
			m, err := load()
			if err != nil {
				logger.Error("failed to reload arbitrary", zap.Error(err))
				return
			}
			a.m.Store(m)
			logger.Info("reloaded arbitrary", zap.Strings("files", changed))
		})
	}
	return a, nil
}

func (a *Arbitrary) Close() error {
	return a.fw.Close()
}

func (a *Arbitrary) Exec(_ context.Context, qCtx *query_context.Context) error {
	if m := a.m.Load(); m != nil {
		if r := m.Reply(qCtx.Q()); r != nil {
			qCtx.SetResponse(r)
			qCtx.SetFromArbitrary()
		}
	}
	return nil
}

func Init(bp *coremain.BP, v any) (any, error) {
	args := v.(*Args)
	return newArbitrary(bp, args, 3*time.Second)
}
