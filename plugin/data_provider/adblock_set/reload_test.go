package adblock_set

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

func waitForMatch(t *testing.T, m domain.Matcher[struct{}], name string, want bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, got := m.Match(name); got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("Match(%q) did not become %v", name, want)
		case <-ticker.C:
		}
	}
}

func writeRules(t *testing.T, path, rules string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProviderReloadsExistingMatcherAfterWriteAndAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	writeRules(t, path, "alpha.example\n")
	args := &Args{Files: []string{path}}
	set, err := newAdblockSet(nil, args, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	matcher := set.GetDomainMatcher()
	waitForMatch(t, matcher, "sub.alpha.example.", true)
	// The provider and watcher must own the configured file list.
	args.Files[0] = filepath.Join(t.TempDir(), "not-the-watched-file")

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					matcher.Match("alpha.example.")
					matcher.Match("second.example.")
					matcher.Match("fourth.example.")
					runtime.Gosched()
				}
			}
		}()
	}
	defer func() { close(stop); readers.Wait() }()
	writeRules(t, path, "second.example\n")
	waitForMatch(t, matcher, "second.example", true)
	waitForMatch(t, matcher, "alpha.example", false)
	oldInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.txt")
	writeRules(t, replacement, "fourth.example\n")
	if err := os.Chtimes(replacement, oldInfo.ModTime(), oldInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	newInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if oldInfo.Size() != newInfo.Size() || !oldInfo.ModTime().Equal(newInfo.ModTime()) {
		t.Fatal("fixture did not preserve size and mtime across replacement")
	}
	waitForMatch(t, matcher, "fourth.example", true)
	waitForMatch(t, matcher, "second.example", false)
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	writeRules(t, path, "closed.example\n")
	if _, found := matcher.Match("fourth.example"); !found {
		t.Fatal("closing provider discarded its final matcher")
	}
	if _, found := matcher.Match("closed.example"); found {
		t.Fatal("provider reloaded after Close returned")
	}
}

func TestProviderKeepsLastGoodMatcherAfterLoadFailureAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	writeRules(t, path, "keep.example\n")
	set, err := newAdblockSet(nil, &Args{Files: []string{path}}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	matcher := set.GetDomainMatcher()
	writeRules(t, path, strings.Repeat("x", 70*1024)) // scanner failure
	deadline := time.NewTimer(80 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if _, found := matcher.Match("keep.example"); !found {
			t.Fatal("failed parse replaced the last working rules")
		}
		select {
		case <-deadline.C:
			goto recoverRules
		case <-ticker.C:
		}
	}

recoverRules:
	writeRules(t, path, "recovered.example\n")
	waitForMatch(t, matcher, "recovered.example", true)
	waitForMatch(t, matcher, "keep.example", false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// A missing source is also retained until it can be successfully rebuilt.
	if _, found := matcher.Match("recovered.example"); !found {
		t.Fatal("removed source discarded active rules")
	}
	writeRules(t, path, "created.example\n")
	waitForMatch(t, matcher, "created.example", true)
}

func TestProviderRejectsUnreadableInitialFile(t *testing.T) {
	if set, err := NewAdblockSet(nil, &Args{Files: []string{filepath.Join(t.TempDir(), "missing")}}); err == nil || set != nil {
		t.Fatal("missing initial rule file was accepted")
	}
}

func TestExceptionsOverrideBlockingRulesAndMalformedRulesDoNotBlockEverything(t *testing.T) {
	blacklist, whitelist := domain.NewMixMatcher[struct{}](), domain.NewMixMatcher[struct{}]()
	rules := "||example.com^\n@@||allowed.example.com^\n0.0.0.0 host.example alias.example # comment\n:: ipv6.example\n^exact.example\nfull:native.example\ndomain:native-domain.example\n@@\n^\n||^\ndomain:\nkeyword:\nregexp:\n/[/\ncosmetic.example##.banner\n"
	if err := ParseRules(strings.NewReader(rules), blacklist, whitelist); err != nil {
		t.Fatal(err)
	}
	matcher := &AdblockMatcher{blacklist: blacklist, whitelist: whitelist}
	for name, want := range map[string]bool{
		"ads.example.com": true, "allowed.example.com": false, "sub.allowed.example.com": false,
		"host.example": true, "alias.example": true, "sub.host.example": false,
		"ipv6.example": true, "sub.ipv6.example": false,
		"exact.example": true, "sub.exact.example": false,
		"native.example": true, "sub.native.example": false,
		"sub.native-domain.example": true, "unrelated.example": false, "cosmetic.example": false,
	} {
		if _, got := matcher.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}
