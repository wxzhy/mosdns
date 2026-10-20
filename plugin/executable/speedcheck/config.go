// Package speedcheck selects addresses from independently executed DNS sources.
package speedcheck

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/prometheus/client_golang/prometheus"
)

const PluginType = "speedcheck"

const (
	ModeBounded  = "bounded"
	ModeWaitAll  = "wait_all"
	maxUniqueIPs = 64
)

// Args describes complete executable source chains, not upstream addresses.
// A nil include list is unrestricted; an explicitly empty include never matches.
type Args struct {
	Sources          []string            `yaml:"sources"`
	Mode             string              `yaml:"mode"`
	TotalTimeout     time.Duration       `yaml:"total_timeout"`
	SelectionTimeout time.Duration       `yaml:"selection_timeout"`
	SettleWindow     time.Duration       `yaml:"settle_window"`
	Probe            speedtest.Config    `yaml:"probe"`
	MaxNum           int                 `yaml:"max_num"`
	ThresholdMS      *float64            `yaml:"threshold_ms"`
	Labels           map[string][]string `yaml:"labels"`
	TagMultipliers   []TagMultiplier     `yaml:"tag_multipliers"`
	ASNMultipliers   map[uint32]float64  `yaml:"asn_multipliers"`
	CandidateFilter  *IPFilter           `yaml:"candidate_filter"`
	ProbeMatch       *IPFilter           `yaml:"probe_match"`
}

type TagMultiplier struct {
	Tag        string  `yaml:"tag"`
	Multiplier float64 `yaml:"multiplier"`
}

type IPFilter struct {
	LabelsInclude []string `yaml:"labels_include"`
	LabelsExclude []string `yaml:"labels_exclude"`
	ASNInclude    []uint32 `yaml:"asn_include"`
	ASNExclude    []uint32 `yaml:"asn_exclude"`
}

type Source struct {
	Tag  string
	Exec sequence.Executable
}

type ProbeFunc func(context.Context, netip.Addr, speedtest.Config) speedtest.Result
type PrepareFunc func(speedtest.Config) (speedtest.Config, error)

// Options permits deterministic, network-free probes and metadata in tests.
// Production Init always uses the process-owned probe manager.
type Options struct {
	Probe       ProbeFunc
	Prepare     PrepareFunc
	Labels      map[string]netlist.Matcher
	ASNMatchers map[uint32]netlist.Matcher
	MetricsTag  string
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, value any) (any, error) {
	args := *value.(*Args)
	sources := make([]Source, 0, len(args.Sources))
	for _, tag := range args.Sources {
		e := sequence.ToExecutable(bp.M().GetPlugin(tag))
		if e == nil {
			return nil, fmt.Errorf("speedcheck: source %q is not an executable", tag)
		}
		sources = append(sources, Source{Tag: tag, Exec: e})
	}
	labels, err := compileLabels(bp, args.Labels)
	if err != nil {
		return nil, err
	}
	asns := make(map[uint32]netlist.Matcher)
	for _, asn := range neededASNs(args) {
		m, err := geodata.GetASNMatcher("", strconv.FormatUint(uint64(asn), 10))
		if err != nil {
			return nil, fmt.Errorf("speedcheck: ASN %d: %w", asn, err)
		}
		asns[asn] = m
	}
	manager := bp.M().ProbeManager()
	s, err := New(args, sources, Options{Probe: manager.Measure, Prepare: manager.Prepare, Labels: labels, ASNMatchers: asns, MetricsTag: bp.Tag()})
	if err != nil {
		return nil, err
	}
	if err := s.RegisterMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func compileLabels(bp *coremain.BP, labels map[string][]string) (map[string]netlist.Matcher, error) {
	result := make(map[string]netlist.Matcher, len(labels))
	for name, expressions := range labels {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("speedcheck: label name is empty")
		}
		group, err := ip_set.CompileExpressions(bp, expressions)
		if err != nil {
			return nil, fmt.Errorf("speedcheck: label %q: %w", name, err)
		}
		result[name] = group
	}
	return result, nil
}

func neededASNs(a Args) []uint32 {
	m := make(map[uint32]struct{})
	for n := range a.ASNMultipliers {
		m[n] = struct{}{}
	}
	for _, f := range []*IPFilter{a.CandidateFilter, a.ProbeMatch} {
		if f != nil {
			for _, n := range append(slices.Clone(f.ASNInclude), f.ASNExclude...) {
				m[n] = struct{}{}
			}
		}
	}
	r := make([]uint32, 0, len(m))
	for n := range m {
		r = append(r, n)
	}
	slices.Sort(r)
	return r
}

func normalize(a Args) (Args, error) {
	if a.Mode == "" {
		a.Mode = ModeBounded
	}
	if a.Mode != ModeBounded && a.Mode != ModeWaitAll {
		return a, fmt.Errorf("speedcheck: invalid mode %q", a.Mode)
	}
	if a.TotalTimeout == 0 {
		a.TotalTimeout = 5 * time.Second
	}
	if a.SelectionTimeout == 0 {
		a.SelectionTimeout = 300 * time.Millisecond
	}
	if a.SettleWindow == 0 {
		a.SettleWindow = 25 * time.Millisecond
	}
	if a.TotalTimeout < 0 || a.SelectionTimeout < 0 || a.SettleWindow < 0 {
		return a, errors.New("speedcheck: timeouts must be positive")
	}
	if a.MaxNum == 0 {
		a.MaxNum = 1
	}
	if a.MaxNum < 1 || a.MaxNum > maxUniqueIPs {
		return a, errors.New("speedcheck: max_num must be within 1..64")
	}
	if a.ThresholdMS == nil {
		v := 100.0
		a.ThresholdMS = &v
	} else {
		v := *a.ThresholdMS
		a.ThresholdMS = &v
	}
	if math.IsNaN(*a.ThresholdMS) || math.IsInf(*a.ThresholdMS, 0) || *a.ThresholdMS < 0 {
		return a, errors.New("speedcheck: threshold_ms must be finite and nonnegative")
	}
	if a.Probe.TCPPorts == nil {
		a.Probe.TCPPorts = []uint16{80, 443}
	} else {
		a.Probe.TCPPorts = slices.Clone(a.Probe.TCPPorts)
	}
	if a.Probe.Timeout == 0 {
		a.Probe.Timeout = 300 * time.Millisecond
	}
	if a.Probe.Timeout < 0 {
		return a, errors.New("speedcheck: probe timeout must be positive")
	}
	for _, p := range a.Probe.TCPPorts {
		if p == 0 {
			return a, errors.New("speedcheck: TCP port must be within 1..65535")
		}
	}
	slices.Sort(a.Probe.TCPPorts)
	a.Probe.TCPPorts = slices.Compact(a.Probe.TCPPorts)
	a.Sources = slices.Clone(a.Sources)
	a.TagMultipliers = slices.Clone(a.TagMultipliers)
	a.ASNMultipliers = maps.Clone(a.ASNMultipliers)
	a.CandidateFilter = cloneFilter(a.CandidateFilter)
	a.ProbeMatch = cloneFilter(a.ProbeMatch)
	return a, nil
}

func cloneFilter(in *IPFilter) *IPFilter {
	if in == nil {
		return nil
	}
	r := *in
	r.LabelsInclude = slices.Clone(in.LabelsInclude)
	r.LabelsExclude = slices.Clone(in.LabelsExclude)
	r.ASNInclude = slices.Clone(in.ASNInclude)
	r.ASNExclude = slices.Clone(in.ASNExclude)
	return &r
}

func (s *Selector) validateMatchers() error {
	for _, f := range []*IPFilter{s.args.CandidateFilter, s.args.ProbeMatch} {
		if f == nil {
			continue
		}
		for _, label := range append(slices.Clone(f.LabelsInclude), f.LabelsExclude...) {
			if s.labels[label] == nil {
				return fmt.Errorf("speedcheck: unknown label %q", label)
			}
		}
	}
	seen := make(map[string]bool)
	for _, w := range s.args.TagMultipliers {
		if seen[w.Tag] {
			return fmt.Errorf("speedcheck: duplicate tag multiplier %q", w.Tag)
		}
		seen[w.Tag] = true
		if s.labels[w.Tag] == nil {
			return fmt.Errorf("speedcheck: unknown multiplier label %q", w.Tag)
		}
		if !validMultiplier(w.Multiplier) {
			return fmt.Errorf("speedcheck: invalid multiplier for %q", w.Tag)
		}
	}
	for asn, w := range s.args.ASNMultipliers {
		if !validMultiplier(w) {
			return fmt.Errorf("speedcheck: invalid multiplier for ASN %d", asn)
		}
	}
	for _, n := range neededASNs(s.args) {
		if s.asns[n] == nil {
			return fmt.Errorf("speedcheck: missing matcher for ASN %d", n)
		}
	}
	for label := range s.labels {
		s.labelNames = append(s.labelNames, label)
	}
	slices.Sort(s.labelNames)
	return nil
}

func validMultiplier(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }

// Check interface at compile time, without making the selector recursive.
var _ sequence.Executable = (*Selector)(nil)
