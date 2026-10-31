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

package hosts

import (
	"bytes"
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/hosts"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

const PluginType = "hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*Hosts)(nil)

type Args struct {
	Entries []string `yaml:"entries"`
	Files   []string `yaml:"files"`
}

type Hosts struct {
	h  atomic.Pointer[hosts.Hosts]
	fw *utils.FileWatcher
}

func Init(bp *coremain.BP, args any) (any, error) {
	return newHosts(bp, args.(*Args), 3*time.Second)
}

func NewHosts(args *Args) (*Hosts, error) {
	return newHosts(nil, args, 3*time.Second)
}

func newHosts(bp *coremain.BP, args *Args, interval time.Duration) (*Hosts, error) {
	if args == nil {
		return nil, fmt.Errorf("hosts: missing args")
	}
	entries, files := slices.Clone(args.Entries), slices.Clone(args.Files)
	load := func() (*hosts.Hosts, error) {
		m := domain.NewMixMatcher[*hosts.IPs]()
		m.SetDefaultMatcher(domain.MatcherFull)
		for i, entry := range entries {
			if err := domain.Load[*hosts.IPs](m, entry, hosts.ParseIPs); err != nil {
				return nil, fmt.Errorf("failed to load entry #%d %s, %w", i, entry, err)
			}
		}
		for i, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file #%d %s, %w", i, file, err)
			}
			if err := domain.LoadFromTextReader[*hosts.IPs](m, bytes.NewReader(b), hosts.ParseIPs); err != nil {
				return nil, fmt.Errorf("failed to load file #%d %s, %w", i, file, err)
			}
		}
		return hosts.NewHosts(m), nil
	}
	initial := utils.SnapshotFileStates(files)
	h, err := load()
	if err != nil {
		return nil, err
	}
	p := &Hosts{}
	p.h.Store(h)
	if len(files) > 0 {
		logger := zap.NewNop()
		if bp != nil {
			logger = bp.L()
		}
		p.fw = utils.StartFileWatcherFromSnapshot(files, initial, interval, func(changed []string) bool {
			h, err := load()
			if err != nil {
				logger.Error("failed to reload hosts", zap.Error(err))
				return false
			}
			p.h.Store(h)
			logger.Info("reloaded hosts", zap.Strings("files", changed))
			return true
		})
	}
	return p, nil
}

func (h *Hosts) Close() error {
	return h.fw.Close()
}

func (h *Hosts) Response(q *dns.Msg) *dns.Msg {
	if matcher := h.h.Load(); matcher != nil {
		return matcher.LookupMsg(q)
	}
	return nil
}

func (h *Hosts) Exec(_ context.Context, qCtx *query_context.Context) error {
	r := h.Response(qCtx.Q())
	if r != nil {
		qCtx.SetResponse(r)
		qCtx.SetFromHosts()
	}
	return nil
}
