/*
 * Copyright (C) 2020-2026, IrineSistiana
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

package stats_api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	PluginType      = "stats_api"
	statsDumpHeader = "mosdns_stats_v1"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.RecursiveExecutable = (*StatsAPI)(nil)

type Args struct {
	Listen       string `yaml:"listen"`
	Capacity     int    `yaml:"capacity"`
	DumpFile     string `yaml:"dump_file"`
	DumpInterval int    `yaml:"dump_interval"`
}

func (a *Args) init() {
	if a.Capacity <= 0 {
		a.Capacity = 2000
	}
	utils.SetDefaultUnsignNum(&a.DumpInterval, 600)
}

type AnswerDTO struct {
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  uint32 `json:"ttl"`
}

type LogEntry struct {
	ID        string      `json:"id"`
	Timestamp string      `json:"timestamp"`
	ClientIP  string      `json:"client_ip"`
	Domain    string      `json:"domain"`
	QType     string      `json:"qtype"`
	Status    string      `json:"status"`
	IsBlocked bool        `json:"is_blocked"`
	IsCached  bool        `json:"is_cached"`
	ElapsedMS float64     `json:"elapsed_ms"`
	Upstream  string      `json:"upstream,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Answers   []AnswerDTO `json:"answers"`
}

type RingBuffer struct {
	mu       sync.RWMutex
	buf      []LogEntry
	capacity int
	head     int
	count    int
	seqID    uint64
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 2000
	}
	return &RingBuffer{
		buf:      make([]LogEntry, capacity),
		capacity: capacity,
	}
}

func (r *RingBuffer) Push(entry LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seqID++
	nowSec := time.Now().Unix()
	entry.ID = fmt.Sprintf("%d-%d", nowSec, r.seqID)
	entry.Answers = slices.Clone(entry.Answers)

	r.buf[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = make([]LogEntry, r.capacity)
	r.head = 0
	r.count = 0
	r.seqID = 0
}

func (r *RingBuffer) QueryLogs(limit, offset int, search, filter string) (int, []LogEntry) {
	searchLower := strings.ToLower(strings.TrimSpace(search))
	filterLower := strings.ToLower(strings.TrimSpace(filter))

	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := make([]LogEntry, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + r.capacity) % r.capacity
		entry := r.buf[idx]
		entry.Answers = slices.Clone(entry.Answers)

		switch filterLower {
		case "blocked":
			if !entry.IsBlocked {
				continue
			}
		case "cached":
			if !entry.IsCached {
				continue
			}
		case "hosts":
			if entry.Upstream != "hosts" && entry.Rule != "hosts" {
				continue
			}
		case "arbitrary":
			if entry.Upstream != "arbitrary" && entry.Rule != "arbitrary" {
				continue
			}
		case "timeout":
			if entry.Status != "TIMEOUT" {
				continue
			}
		case "error":
			if entry.Status != "ERROR" {
				continue
			}
		case "all", "":
			// no filter
		default:
			if !strings.EqualFold(entry.Status, filterLower) {
				continue
			}
		}

		if searchLower != "" {
			if !strings.Contains(strings.ToLower(entry.Domain), searchLower) &&
				!strings.Contains(strings.ToLower(entry.ClientIP), searchLower) {
				continue
			}
		}

		filtered = append(filtered, entry)
	}

	total := len(filtered)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return total, []LogEntry{}
	}

	end := offset + min(max(limit, 0), total-offset)

	return total, filtered[offset:end]
}

// Export returns logs in chronological order (oldest first) and current seqID.
func (r *RingBuffer) Export() ([]LogEntry, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]LogEntry, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head - r.count + i + r.capacity) % r.capacity
		entry := r.buf[idx]
		entry.Answers = slices.Clone(entry.Answers)
		entries = append(entries, entry)
	}
	return entries, r.seqID
}

// Import restores logs into ring buffer adapting to current capacity.
func (r *RingBuffer) Import(entries []LogEntry, seqID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = make([]LogEntry, r.capacity)
	r.head = 0
	r.count = 0
	r.seqID = seqID

	start := 0
	if len(entries) > r.capacity {
		start = len(entries) - r.capacity
	}
	for i := start; i < len(entries); i++ {
		r.buf[r.head] = entries[i]
		r.buf[r.head].Answers = slices.Clone(entries[i].Answers)
		r.head = (r.head + 1) % r.capacity
		if r.count < r.capacity {
			r.count++
		}
	}
}

type TopItem struct {
	Domain   string `json:"domain,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Count    uint64 `json:"count"`
}

type TopStats struct {
	mu         sync.RWMutex
	topDomains map[string]uint64
	topClients map[string]uint64
	topBlocked map[string]uint64
}

func NewTopStats() *TopStats {
	return &TopStats{
		topDomains: make(map[string]uint64),
		topClients: make(map[string]uint64),
		topBlocked: make(map[string]uint64),
	}
}

const maxTopEntries = 20000

func pruneMap(m map[string]uint64) {
	if len(m) <= maxTopEntries {
		return
	}
	for k, v := range m {
		if v <= 1 {
			delete(m, k)
		}
	}
	if len(m) > maxTopEntries {
		for k, v := range m {
			if v <= 2 {
				delete(m, k)
			}
		}
	}
}

func (t *TopStats) Record(domain, clientIP string, isBlocked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if domain != "" {
		domainLower := strings.ToLower(domain)
		if isBlocked {
			t.topBlocked[domainLower]++
			if len(t.topBlocked) > maxTopEntries {
				pruneMap(t.topBlocked)
			}
		} else {
			t.topDomains[domainLower]++
			if len(t.topDomains) > maxTopEntries {
				pruneMap(t.topDomains)
			}
		}
	}
	if clientIP != "" {
		t.topClients[clientIP]++
		if len(t.topClients) > maxTopEntries {
			pruneMap(t.topClients)
		}
	}
}

func (t *TopStats) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.topDomains = make(map[string]uint64)
	t.topClients = make(map[string]uint64)
	t.topBlocked = make(map[string]uint64)
}

func (t *TopStats) Export() (map[string]uint64, map[string]uint64, map[string]uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domains := make(map[string]uint64, len(t.topDomains))
	for k, v := range t.topDomains {
		domains[k] = v
	}
	clients := make(map[string]uint64, len(t.topClients))
	for k, v := range t.topClients {
		clients[k] = v
	}
	blocked := make(map[string]uint64, len(t.topBlocked))
	for k, v := range t.topBlocked {
		blocked[k] = v
	}
	return domains, clients, blocked
}

func (t *TopStats) Import(domains, clients, blocked map[string]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.topDomains = make(map[string]uint64, len(domains))
	for k, v := range domains {
		t.topDomains[k] = v
	}
	t.topClients = make(map[string]uint64, len(clients))
	for k, v := range clients {
		t.topClients[k] = v
	}
	t.topBlocked = make(map[string]uint64, len(blocked))
	for k, v := range blocked {
		t.topBlocked[k] = v
	}
}

func (t *TopStats) GetTop(limit int) ([]TopItem, []TopItem, []TopItem) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}

	type pair struct {
		key   string
		count uint64
	}

	sortPairs := func(pairs []pair, isClient bool) []TopItem {
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].count == pairs[j].count {
				return pairs[i].key < pairs[j].key
			}
			return pairs[i].count > pairs[j].count
		})

		n := limit
		if n > len(pairs) {
			n = len(pairs)
		}
		res := make([]TopItem, 0, n)
		for i := 0; i < n; i++ {
			item := TopItem{Count: pairs[i].count}
			if isClient {
				item.ClientIP = pairs[i].key
			} else {
				item.Domain = pairs[i].key
			}
			res = append(res, item)
		}
		return res
	}

	domainPairs := make([]pair, 0, len(t.topDomains))
	for domain, count := range t.topDomains {
		if _, isBlocked := t.topBlocked[domain]; !isBlocked {
			domainPairs = append(domainPairs, pair{key: domain, count: count})
		}
	}

	clientPairs := make([]pair, 0, len(t.topClients))
	for client, count := range t.topClients {
		clientPairs = append(clientPairs, pair{key: client, count: count})
	}

	blockedPairs := make([]pair, 0, len(t.topBlocked))
	for blocked, count := range t.topBlocked {
		blockedPairs = append(blockedPairs, pair{key: blocked, count: count})
	}

	topDomains := sortPairs(domainPairs, false)
	topClients := sortPairs(clientPairs, true)
	topBlocked := sortPairs(blockedPairs, false)
	return topDomains, topClients, topBlocked
}

type HistoryPoint struct {
	Time    string `json:"time"`
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
	Cached  uint64 `json:"cached"`
}

type HistoryBucket struct {
	Total   atomic.Uint64
	Blocked atomic.Uint64
	Cached  atomic.Uint64
}

type HistoryBucketData struct {
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
	Cached  uint64 `json:"cached"`
}

type HistoryStats struct {
	mu     sync.RWMutex
	points map[int64]*HistoryBucket
}

func NewHistoryStats() *HistoryStats {
	return &HistoryStats{
		points: make(map[int64]*HistoryBucket),
	}
}

func (h *HistoryStats) Record(t time.Time, isBlocked, isCached bool) {
	tHour := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Unix()

	h.mu.RLock()
	bucket, ok := h.points[tHour]
	h.mu.RUnlock()

	if !ok {
		h.mu.Lock()
		bucket, ok = h.points[tHour]
		if !ok {
			bucket = &HistoryBucket{}
			h.points[tHour] = bucket

			// Clean up old buckets beyond 168 hours (7 days)
			cutoff := t.Add(-168 * time.Hour).Unix()
			for k := range h.points {
				if k < cutoff {
					delete(h.points, k)
				}
			}
		}
		h.mu.Unlock()
	}

	bucket.Total.Add(1)
	if isBlocked {
		bucket.Blocked.Add(1)
	}
	if isCached {
		bucket.Cached.Add(1)
	}
}

func (h *HistoryStats) GetHistory(numPoints int) []HistoryPoint {
	if numPoints <= 0 {
		numPoints = 24
	}
	now := time.Now()
	nowHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	res := make([]HistoryPoint, 0, numPoints)

	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := numPoints - 1; i >= 0; i-- {
		slotTime := nowHour.Add(time.Duration(-i) * time.Hour)
		slotUnix := slotTime.Unix()

		var total, blocked, cached uint64
		if bucket, ok := h.points[slotUnix]; ok {
			total = bucket.Total.Load()
			blocked = bucket.Blocked.Load()
			cached = bucket.Cached.Load()
		}

		res = append(res, HistoryPoint{
			Time:    slotTime.Format(time.RFC3339),
			Total:   total,
			Blocked: blocked,
			Cached:  cached,
		})
	}
	return res
}

func (h *HistoryStats) Export() map[int64]HistoryBucketData {
	h.mu.RLock()
	defer h.mu.RUnlock()

	res := make(map[int64]HistoryBucketData, len(h.points))
	for k, v := range h.points {
		if v != nil {
			res[k] = HistoryBucketData{
				Total:   v.Total.Load(),
				Blocked: v.Blocked.Load(),
				Cached:  v.Cached.Load(),
			}
		}
	}
	return res
}

func (h *HistoryStats) Import(points map[int64]HistoryBucketData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.points = make(map[int64]*HistoryBucket, len(points))
	cutoff := time.Now().Add(-168 * time.Hour).Unix()
	for k, v := range points {
		if k >= cutoff {
			bucket := &HistoryBucket{}
			bucket.Total.Store(v.Total)
			bucket.Blocked.Store(v.Blocked)
			bucket.Cached.Store(v.Cached)
			h.points[k] = bucket
		}
	}
}

type StatsDumpData struct {
	Version          int                         `json:"version"`
	Timestamp        int64                       `json:"timestamp"`
	TotalQueries     uint64                      `json:"total_queries"`
	BlockedQueries   uint64                      `json:"blocked_queries"`
	CachedQueries    uint64                      `json:"cached_queries"`
	HostsQueries     uint64                      `json:"hosts_queries,omitempty"`
	ArbitraryQueries uint64                      `json:"arbitrary_queries,omitempty"`
	TimeoutQueries   uint64                      `json:"timeout_queries,omitempty"`
	TotalLatencyUs   uint64                      `json:"total_latency_us"`
	LatencyQueries   uint64                      `json:"latency_queries,omitempty"`
	TopDomains       map[string]uint64           `json:"top_domains,omitempty"`
	TopClients       map[string]uint64           `json:"top_clients,omitempty"`
	TopBlocked       map[string]uint64           `json:"top_blocked,omitempty"`
	History          map[int64]HistoryBucketData `json:"history,omitempty"`
	Logs             []LogEntry                  `json:"logs,omitempty"`
	SeqID            uint64                      `json:"seq_id,omitempty"`
}

type StatsAPI struct {
	args   *Args
	logger *zap.Logger
	m      *coremain.Mosdns
	tag    string

	ringBuffer   *RingBuffer
	topStats     *TopStats
	historyStats *HistoryStats

	totalQueries     atomic.Uint64
	blockedQueries   atomic.Uint64
	cachedQueries    atomic.Uint64
	hostsQueries     atomic.Uint64
	arbitraryQueries atomic.Uint64
	timeoutQueries   atomic.Uint64
	totalLatencyUs   atomic.Uint64
	latencyQueries   atomic.Uint64
	currentQPS       atomic.Uint64

	updatedCount atomic.Uint64
	closeNotify  chan struct{}
	httpServer   *http.Server
	closeOnce    sync.Once
	// Keep each completed query's counters, history and logs together when
	// exporting or replacing a dump. Individual containers retain their locks.
	stateMu      sync.RWMutex
	dumpMu       sync.Mutex
	preserveDump bool
	lifecycleMu  sync.Mutex
	closing      bool
	queries      sync.WaitGroup
	loops        sync.WaitGroup
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	s := NewStatsAPI(a, bp.L())
	s.stateMu.Lock()
	s.m = bp.M()
	s.tag = bp.Tag()
	s.stateMu.Unlock()
	bp.RegAPI(s.Router())
	return s, nil
}

func QuickSetup(bq sequence.BQ, s string) (any, error) {
	fields := strings.Fields(s)
	listen := ""
	capacity := 2000
	dumpFile := ""
	dumpInterval := 600
	if len(fields) > 0 {
		listen = fields[0]
	}
	if len(fields) > 1 {
		if c, err := strconv.Atoi(fields[1]); err == nil && c > 0 {
			capacity = c
		}
	}
	if len(fields) > 2 {
		dumpFile = fields[2]
	}
	if len(fields) > 3 {
		if d, err := strconv.Atoi(fields[3]); err == nil && d > 0 {
			dumpInterval = d
		}
	}
	api := NewStatsAPI(&Args{
		Listen:       listen,
		Capacity:     capacity,
		DumpFile:     dumpFile,
		DumpInterval: dumpInterval,
	}, bq.L())
	api.stateMu.Lock()
	api.m = bq.M()
	api.stateMu.Unlock()
	return api, nil
}

func NewStatsAPI(args *Args, logger *zap.Logger) *StatsAPI {
	args.init()
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &StatsAPI{
		args:         args,
		logger:       logger,
		ringBuffer:   NewRingBuffer(args.Capacity),
		topStats:     NewTopStats(),
		historyStats: NewHistoryStats(),
		closeNotify:  make(chan struct{}),
	}

	if err := s.loadDump(); err != nil {
		s.preserveDump = true
		s.logger.Error("failed to load stats dump; preserving file and disabling persistence", zap.Error(err))
	}
	s.startDumpLoop()
	s.startQPSLoop()

	if len(args.Listen) > 0 {
		srv := &http.Server{
			Addr:              args.Listen,
			Handler:           s.Router(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		s.httpServer = srv
		s.loops.Add(1)
		go func() {
			defer s.loops.Done()
			logger.Info("starting stats api http server", zap.String("addr", args.Listen))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("stats api http server error", zap.Error(err))
			}
		}()
	}
	return s
}

func (s *StatsAPI) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/api/v1/stats", s.handleStats)
	r.Get("/api/v1/logs", s.handleLogs)
	r.Get("/api/v1/top", s.handleTop)
	r.Get("/api/v1/history", s.handleHistory)
	r.Get("/api/v1/dump", s.handleDump)
	r.Post("/api/v1/load_dump", s.handleLoadDump)
	r.Post("/api/v1/logs/clear", s.handleClearLogs)
	r.Post("/api/v1/cache/clear", s.handleClearCache)

	// Relative endpoints when mounted under a prefix (e.g. /plugins/<tag>/stats)
	r.Get("/stats", s.handleStats)
	r.Get("/logs", s.handleLogs)
	r.Get("/top", s.handleTop)
	r.Get("/history", s.handleHistory)
	r.Get("/dump", s.handleDump)
	r.Post("/load_dump", s.handleLoadDump)
	r.Post("/logs/clear", s.handleClearLogs)
	r.Post("/cache/clear", s.handleClearCache)

	return r
}

func (s *StatsAPI) handleStats(w http.ResponseWriter, req *http.Request) {
	s.stateMu.RLock()
	total := s.totalQueries.Load()
	blocked := s.blockedQueries.Load()
	cached := s.cachedQueries.Load()
	hosts := s.hostsQueries.Load()
	arbitrary := s.arbitraryQueries.Load()
	timeout := s.timeoutQueries.Load()
	latUs := s.totalLatencyUs.Load()
	latQueries := s.latencyQueries.Load()

	var blockedPct, cachedPct, timeoutPct, avgLat float64
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100.0
		if blockedPct > 100.0 {
			blockedPct = 100.0
		}
		timeoutPct = float64(timeout) / float64(total) * 100.0
		if timeoutPct > 100.0 {
			timeoutPct = 100.0
		}
	}
	if latQueries > 0 {
		avgLat = (float64(latUs) / float64(latQueries)) / 1000.0
	}
	excluded := blocked + hosts + arbitrary
	if total > excluded {
		cachedPct = float64(cached) / float64(total-excluded) * 100.0
		if cachedPct > 100.0 {
			cachedPct = 100.0
		}
	}

	blockedPct = math.Round(blockedPct*100) / 100
	cachedPct = math.Round(cachedPct*100) / 100
	timeoutPct = math.Round(timeoutPct*100) / 100
	avgLat = math.Round(avgLat*100) / 100
	qps := s.currentQPS.Load()
	s.stateMu.RUnlock()

	resp := map[string]any{
		"total_queries":      total,
		"blocked_queries":    blocked,
		"cached_queries":     cached,
		"hosts_queries":      hosts,
		"arbitrary_queries":  arbitrary,
		"timeout_queries":    timeout,
		"blocked_percentage": blockedPct,
		"cached_percentage":  cachedPct,
		"timeout_percentage": timeoutPct,
		"avg_latency_ms":     avgLat,
		"qps":                qps,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *StatsAPI) handleLogs(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")
	search := q.Get("search")
	filter := q.Get("filter")

	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	total, items := s.ringBuffer.QueryLogs(limit, offset, search, filter)
	if items == nil {
		items = []LogEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total": total,
		"items": items,
	})
}

func (s *StatsAPI) handleTop(w http.ResponseWriter, req *http.Request) {
	limitStr := req.URL.Query().Get("limit")
	limit := 10
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	topDomains, topClients, topBlocked := s.topStats.GetTop(limit)
	if topDomains == nil {
		topDomains = []TopItem{}
	}
	if topClients == nil {
		topClients = []TopItem{}
	}
	if topBlocked == nil {
		topBlocked = []TopItem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"top_domains": topDomains,
		"top_clients": topClients,
		"top_blocked": topBlocked,
	})
}

func (s *StatsAPI) handleHistory(w http.ResponseWriter, req *http.Request) {
	pointsStr := req.URL.Query().Get("points")
	numPoints := 24
	if p, err := strconv.Atoi(pointsStr); err == nil && p > 0 {
		numPoints = p
	}
	if numPoints > 168 { // Max 7 days of hourly points
		numPoints = 168
	}

	points := s.historyStats.GetHistory(numPoints)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"points": points,
	})
}

func (s *StatsAPI) handleDump(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := s.writeDump(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *StatsAPI) handleLoadDump(w http.ResponseWriter, req *http.Request) {
	if err := s.readDump(io.LimitReader(req.Body, 100<<20)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.updatedCount.Add(1)
	w.WriteHeader(http.StatusOK)
}

func (s *StatsAPI) handleClearLogs(w http.ResponseWriter, req *http.Request) {
	s.stateMu.Lock()
	s.ringBuffer.Clear()
	s.topStats.Clear()
	s.updatedCount.Add(1)
	s.stateMu.Unlock()
	_ = s.dumpStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Logs cleared successfully",
	})
}

func (s *StatsAPI) handleClearCache(w http.ResponseWriter, req *http.Request) {
	s.stateMu.RLock()
	m := s.m
	s.stateMu.RUnlock()
	if m != nil {
		m.FlushAllCaches()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Cache clear request processed",
	})
}

func (s *StatsAPI) writeDump(w io.Writer) error {
	gw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	gw.Name = statsDumpHeader

	s.stateMu.RLock()
	data := StatsDumpData{
		Version:          1,
		Timestamp:        time.Now().Unix(),
		TotalQueries:     s.totalQueries.Load(),
		BlockedQueries:   s.blockedQueries.Load(),
		CachedQueries:    s.cachedQueries.Load(),
		HostsQueries:     s.hostsQueries.Load(),
		ArbitraryQueries: s.arbitraryQueries.Load(),
		TimeoutQueries:   s.timeoutQueries.Load(),
		TotalLatencyUs:   s.totalLatencyUs.Load(),
		LatencyQueries:   s.latencyQueries.Load(),
	}

	data.TopDomains, data.TopClients, data.TopBlocked = s.topStats.Export()
	data.History = s.historyStats.Export()
	data.Logs, data.SeqID = s.ringBuffer.Export()
	s.stateMu.RUnlock()

	if err := json.NewEncoder(gw).Encode(&data); err != nil {
		_ = gw.Close()
		return fmt.Errorf("failed to encode stats dump: %w", err)
	}

	return gw.Close()
}

func (s *StatsAPI) readDump(r io.Reader) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	if gr.Name != statsDumpHeader {
		return fmt.Errorf("invalid stats dump header: got %s, want %s", gr.Name, statsDumpHeader)
	}

	var data StatsDumpData
	decoder := json.NewDecoder(gr)
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("failed to decode stats dump: %w", err)
	}
	// Read through the gzip footer before changing live statistics. A truncated
	// or corrupt stream must leave both the current state and old file intact.
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid trailing stats dump data: %v", err)
	}
	if data.Version != 1 {
		return fmt.Errorf("unsupported stats dump version: %d", data.Version)
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.totalQueries.Store(data.TotalQueries)
	s.blockedQueries.Store(data.BlockedQueries)
	s.cachedQueries.Store(data.CachedQueries)
	s.hostsQueries.Store(data.HostsQueries)
	s.arbitraryQueries.Store(data.ArbitraryQueries)
	s.timeoutQueries.Store(data.TimeoutQueries)
	s.totalLatencyUs.Store(data.TotalLatencyUs)
	latQueries := data.LatencyQueries
	if latQueries == 0 && data.TotalQueries > data.TimeoutQueries {
		latQueries = data.TotalQueries - data.TimeoutQueries
	}
	s.latencyQueries.Store(latQueries)

	s.topStats.Import(data.TopDomains, data.TopClients, data.TopBlocked)
	s.historyStats.Import(data.History)
	s.ringBuffer.Import(data.Logs, data.SeqID)

	return nil
}

func (s *StatsAPI) loadDump() error {
	if len(s.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Open(s.args.DumpFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.logger.Info("stats dump file does not exist, starting with empty stats", zap.String("file", s.args.DumpFile))
			return nil
		}
		return err
	}
	defer f.Close()

	if err := s.readDump(f); err != nil {
		return err
	}
	s.logger.Info("stats dump loaded successfully", zap.String("file", s.args.DumpFile))
	return nil
}

func (s *StatsAPI) dumpStats() error {
	if len(s.args.DumpFile) == 0 || s.preserveDump {
		return nil
	}
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	if dir := filepath.Dir(s.args.DumpFile); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	tmpFile := fmt.Sprintf("%s.tmp.%d", s.args.DumpFile, time.Now().UnixNano())
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	if err := s.writeDump(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to write stats dump, %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to sync stats dump, %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to close stats dump, %w", err)
	}

	if err := os.Rename(tmpFile, s.args.DumpFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit stats dump: %w", err)
	}

	s.logger.Info("stats dumped successfully", zap.String("file", s.args.DumpFile))
	return nil
}

func (s *StatsAPI) startDumpLoop() {
	if len(s.args.DumpFile) == 0 || s.preserveDump {
		return
	}
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		ticker := time.NewTicker(time.Duration(s.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if s.updatedCount.Swap(0) > 0 {
					if err := s.dumpStats(); err != nil {
						s.logger.Error("failed to dump stats", zap.Error(err))
						s.updatedCount.Add(1)
					}
				}
			case <-s.closeNotify:
				return
			}
		}
	}()
}

func (s *StatsAPI) startQPSLoop() {
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		const windowSize = 5
		history := make([]uint64, windowSize)
		timestamps := make([]int64, windowSize)
		lastTotal := s.totalQueries.Load()

		for {
			select {
			case now := <-ticker.C:
				curTotal := s.totalQueries.Load()
				var delta uint64
				if curTotal >= lastTotal {
					delta = curTotal - lastTotal
				}
				lastTotal = curTotal

				nowSec := now.Unix()
				idx := int(nowSec % windowSize)
				history[idx] = delta
				timestamps[idx] = nowSec

				var sum uint64
				validSecs := 0
				for i := 0; i < windowSize; i++ {
					if timestamps[i] > 0 && nowSec-timestamps[i] < windowSize {
						sum += history[i]
						validSecs++
					}
				}

				var qps uint64
				if validSecs > 0 {
					qps = (sum + uint64(validSecs)/2) / uint64(validSecs)
				}
				s.currentQPS.Store(qps)

			case <-s.closeNotify:
				return
			}
		}
	}()
}

func isLoopbackDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	return d == "localhost" ||
		strings.HasSuffix(d, ".localhost") ||
		d == "localhost.localdomain" ||
		d == "ip6-localhost" ||
		d == "ip6-loopback"
}

func (s *StatsAPI) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		return next.ExecNext(ctx, qCtx)
	}
	s.queries.Add(1)
	s.lifecycleMu.Unlock()
	defer s.queries.Done()
	start := time.Now()
	err := next.ExecNext(ctx, qCtx)
	elapsed := time.Since(start)

	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.totalQueries.Add(1)
	s.updatedCount.Add(1)

	var clientIP string
	if clientAddr := qCtx.ServerMeta.ClientAddr; clientAddr.IsValid() {
		clientIP = clientAddr.String()
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	qQuestion := qCtx.QQuestion()
	domain := qQuestion.Name
	qtypeStr := dns.TypeToString[qQuestion.Qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qQuestion.Qtype)
	}

	isCached := qCtx.CacheState.Hit || qCtx.CacheState.LazyHit

	hasUpstream := isCached || qCtx.UpstreamSelected != nil

	r := qCtx.R()
	var status string
	answers := make([]AnswerDTO, 0)
	isBlocked := false

	isTimeout := false
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "deadline") ||
			strings.Contains(errStr, "all upstream servers failed") ||
			strings.Contains(errStr, "all primary and secondary executables failed") {
			isTimeout = true
		}
	}
	if elapsed >= 4*time.Second && r == nil {
		isTimeout = true
	}

	if err != nil {
		// Preserve the historical TIMEOUT classification, but never report
		// a stale NOERROR response when the execution ultimately failed.
		status = "SERVFAIL"
		if isTimeout && r == nil {
			status = "TIMEOUT"
		}
		answers = answers[:0]
		isBlocked = false
	} else if r == nil {
		if isTimeout {
			status = "TIMEOUT"
			isBlocked = false
		} else if err != nil {
			status = "ERROR"
			isBlocked = false
		} else {
			status = "DROPPED"
			if !hasUpstream {
				isBlocked = true
			}
		}
	} else {
		if rcodeStr, ok := dns.RcodeToString[r.Rcode]; ok {
			status = rcodeStr
		} else {
			status = fmt.Sprintf("RCODE%d", r.Rcode)
		}

		if !hasUpstream && (r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeRefused) &&
			qQuestion.Qtype != dns.TypeHTTPS && qQuestion.Qtype != dns.TypeSVCB {
			isBlocked = true
		}

		for _, rr := range r.Answer {
			hdr := rr.Header()
			rrTypeStr := dns.TypeToString[hdr.Rrtype]
			if rrTypeStr == "" {
				rrTypeStr = fmt.Sprintf("TYPE%d", hdr.Rrtype)
			}
			var dataStr string
			switch record := rr.(type) {
			case *dns.A:
				dataStr = record.A.String()
				if dataStr == "0.0.0.0" || (dataStr == "127.0.0.1" && !isLoopbackDomain(domain)) {
					isBlocked = true
				}
			case *dns.AAAA:
				dataStr = record.AAAA.String()
				if dataStr == "::" || (dataStr == "::1" && !isLoopbackDomain(domain)) {
					isBlocked = true
				}
			case *dns.CNAME:
				dataStr = record.Target
			case *dns.TXT:
				dataStr = strings.Join(record.Txt, " ")
			case *dns.PTR:
				dataStr = record.Ptr
			case *dns.MX:
				dataStr = record.Mx
			case *dns.NS:
				dataStr = record.Ns
			case *dns.SRV:
				dataStr = fmt.Sprintf("%d %d %d %s", record.Priority, record.Weight, record.Port, record.Target)
			default:
				dataStr = rr.String()
			}
			answers = append(answers, AnswerDTO{
				Type: rrTypeStr,
				Data: dataStr,
				TTL:  hdr.Ttl,
			})
		}
	}

	if isBlocked {
		s.blockedQueries.Add(1)
	}

	// Excluded local/blocked responses must not increase the numerator
	// of the cache-hit percentage for eligible DNS responses.
	if isCached && !isBlocked && !qCtx.FromHosts && !qCtx.FromArbitrary {
		s.cachedQueries.Add(1)
	}

	if isTimeout {
		s.timeoutQueries.Add(1)
	} else {
		s.totalLatencyUs.Add(uint64(elapsed.Microseconds()))
		s.latencyQueries.Add(1)
	}

	isHosts := qCtx.FromHosts && !isBlocked && !isCached && qCtx.UpstreamSelected == nil
	if isHosts {
		s.hostsQueries.Add(1)
	}

	isArbitrary := qCtx.FromArbitrary && !isBlocked && !isCached && qCtx.UpstreamSelected == nil
	if isArbitrary {
		s.arbitraryQueries.Add(1)
	}

	// Extract Upstream information
	var upstream string
	if isCached {
		upstream = "cache"
	} else if isHosts {
		upstream = "hosts"
	} else if isArbitrary {
		upstream = "arbitrary"
	} else if u := qCtx.UpstreamSelected; u != nil {
		if u.Addr != "" {
			if !strings.Contains(u.Addr, "://") {
				if u.Protocol == "DoH" {
					upstream = "https://" + u.Addr
				} else if u.Protocol == "DoT" {
					upstream = "tls://" + u.Addr
				} else if u.Protocol == "DoQ" {
					upstream = "quic://" + u.Addr
				} else {
					upstream = u.Addr
				}
			} else {
				upstream = u.Addr
			}
		} else if u.Tag != "" {
			upstream = u.Tag
		}
	}

	// Extract Rule information
	var rule string
	for i := len(qCtx.RuleHits) - 1; i >= 0; i-- {
		hit := qCtx.RuleHits[i]
		exec := strings.TrimSpace(hit.Exec)

		if exec == "accept" || exec == "return" || strings.HasPrefix(exec, "jump ") || strings.HasPrefix(exec, "ttl ") {
			continue
		}

		var positiveMatches []string
		for _, m := range hit.Matches {
			m = strings.TrimSpace(m)
			if m != "" && m != "has_resp" && !strings.HasPrefix(m, "!") {
				positiveMatches = append(positiveMatches, m)
			}
		}

		if len(positiveMatches) > 0 {
			rule = strings.Join(positiveMatches, ",")
			break
		}

		if exec != "" && exec != "$stats_collector" && exec != "stats_api" && (s.tag == "" || exec != s.tag) {
			rule = exec
			break
		}

		if hit.Sequence != "" && hit.Sequence != "has_resp_sequence" && hit.Sequence != "main_sequence" && (s.tag == "" || hit.Sequence != s.tag) {
			rule = hit.Sequence
			break
		}
	}

	if rule == "" {
		if isCached {
			rule = "cache"
		} else if isHosts {
			rule = "hosts"
		} else if isArbitrary {
			rule = "arbitrary"
		} else if isBlocked {
			rule = "block"
		} else {
			rule = "-"
		}
	}

	s.topStats.Record(domain, clientIP, isBlocked)
	s.historyStats.Record(start, isBlocked, isCached)

	elapsedMS := math.Round(float64(elapsed.Microseconds())/10.0) / 100.0

	entry := LogEntry{
		Timestamp: start.Format(time.RFC3339),
		ClientIP:  clientIP,
		Domain:    domain,
		QType:     qtypeStr,
		Status:    status,
		IsBlocked: isBlocked,
		IsCached:  isCached,
		ElapsedMS: elapsedMS,
		Upstream:  upstream,
		Rule:      rule,
		Answers:   answers,
	}

	s.ringBuffer.Push(entry)

	return err
}

func (s *StatsAPI) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closing = true
		s.lifecycleMu.Unlock()
		close(s.closeNotify)
		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpServer.Shutdown(ctx)
		}
		s.loops.Wait()
		s.queries.Wait()
		if err := s.dumpStats(); err != nil {
			s.logger.Error("failed to dump stats on close", zap.Error(err))
		}
	})
	return nil
}
