package stats_api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/gzip"
)

func TestStatsDumpRejectsInconsistentCountersWithoutMutatingState(t *testing.T) {
	s := NewStatsAPI(&Args{}, nil)
	defer s.Close()
	s.totalQueries.Store(3)
	tests := []StatsDumpData{
		{Version: 1, TotalQueries: 1, BlockedQueries: 2},
		{Version: 1, TotalQueries: 2, BlockedQueries: 1, CachedQueries: 3},
		{Version: 1, TotalQueries: 2, LatencyQueries: 3},
	}
	for _, tc := range tests {
		var b bytes.Buffer
		gw := gzip.NewWriter(&b)
		gw.Name = statsDumpHeader
		if err := json.NewEncoder(gw).Encode(tc); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.readDump(&b); err == nil || !strings.Contains(err.Error(), "invalid stats dump") {
			t.Fatalf("expected validation failure for %+v: %v", tc, err)
		}
		if s.totalQueries.Load() != 3 {
			t.Fatal("invalid dump changed live statistics")
		}
	}
}

func TestStatsDumpImportDoesNotGenerateLiveQPS(t *testing.T) {
	s := NewStatsAPI(&Args{}, nil)
	defer s.Close()
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	gw.Name = statsDumpHeader
	if err := json.NewEncoder(gw).Encode(StatsDumpData{Version: 1, TotalQueries: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.readDump(&b); err != nil {
		t.Fatal(err)
	}
	if s.liveQueries.Load() != 0 {
		t.Fatal("imported history was counted as live queries")
	}
	time.Sleep(1100 * time.Millisecond)
	if s.currentQPS.Load() != 0 {
		t.Fatalf("historical import generated spurious QPS: %d", s.currentQPS.Load())
	}
}
