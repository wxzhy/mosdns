package stats_api

import (
	"testing"
	"time"
)

func TestHistoryDistinctRepeatedLocalHour(t *testing.T) {
	z, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("timezone not available: %v", err)
	}
	first := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC).In(z)
	second := first.Add(time.Hour)
	if first.Hour() != second.Hour() || first.Day() != second.Day() {
		t.Fatal("fixture does not represent fall-back hour")
	}
	h := NewHistoryStats()
	h.Record(first, false, false)
	h.Record(second, true, false)
	points := h.Export()
	if len(points) != 2 {
		t.Fatalf("DST repeated hours merged: %+v", points)
	}
	for _, ts := range []int64{first.UTC().Truncate(time.Hour).Unix(), second.UTC().Truncate(time.Hour).Unix()} {
		if points[ts].Total != 1 {
			t.Fatalf("unexpected hourly bucket %d: %+v", ts, points[ts])
		}
	}
}
