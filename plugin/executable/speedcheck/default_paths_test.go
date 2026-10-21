package speedcheck

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
)

func TestNumericASNUsesDefaultPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configured-asn.mmdb")
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(nil, geodata.Paths{ASN: path}))
	for _, args := range []*Args{
		{ASNMultipliers: map[uint32]float64{13335: 0.5}},
		{CandidateFilter: &IPFilter{ASNInclude: []uint32{13335}}},
		{ProbeMatch: &IPFilter{ASNExclude: []uint32{13335}}},
	} {
		_, err := Init(bp, args)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("error = %v, want a read error from configured path %q", err, path)
		}
	}
}
