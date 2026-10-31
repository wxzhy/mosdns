package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func TestCommitResponseModes(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mode           CommitMode
		keepParentMark bool
		keepParentKV   bool
	}{
		{name: "merge", mode: CommitMerge, keepParentMark: true, keepParentKV: true},
		{name: "replace", mode: CommitReplace},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := NewContext(new(dns.Msg).SetQuestion("parent.example.", dns.TypeA))
			updatedKey, preservedKey := RegKey(), RegKey()
			parent.SetMark(7)
			parent.StoreValue(updatedKey, "parent")
			parent.StoreValue(preservedKey, "keep")

			branch := parent.Copy()
			branch.SetResponse(new(dns.Msg).SetReply(branch.Q()))
			branch.DeleteMark(7)
			branch.SetMark(8)
			branch.StoreValue(updatedKey, "winner")
			branch.DeleteValue(preservedKey)
			snapshot := branch.SnapshotResponse()

			// A completed snapshot cannot be changed through later branch writes.
			branch.SetMark(9)
			branch.StoreValue(updatedKey, "late")
			parent.CommitResponse(snapshot, tc.mode)
			if parent.HasMark(7) != tc.keepParentMark || !parent.HasMark(8) || parent.HasMark(9) {
				t.Fatalf("wrong marks after %s", tc.name)
			}
			if got, _ := parent.GetValue(updatedKey); got != "winner" {
				t.Fatalf("winner KV not committed: %v", got)
			}
			_, retained := parent.GetValue(preservedKey)
			if retained != tc.keepParentKV {
				t.Fatal("wrong handling of parent-only KV")
			}
			if parent.QQuestion().Name != "parent.example." || parent.R() == nil {
				t.Fatal("commit modified parent query or dropped winner response")
			}
			// A committed snapshot must not share the original maps.
			snapshot.marks[10] = struct{}{}
			snapshot.kv[updatedKey] = "snapshot mutated"
			if parent.HasMark(10) {
				t.Fatal("snapshot shares marks with the committed parent")
			}
			if got, _ := parent.GetValue(updatedKey); got != "winner" {
				t.Fatal("snapshot shares KV map with the committed parent")
			}
		})
	}
}

func TestCommitResponseReplaceEmptyAndDefaultIsolation(t *testing.T) {
	parent := NewContext(new(dns.Msg).SetQuestion("parent.example.", dns.TypeA))
	key := RegKey()
	parent.SetMark(7)
	parent.StoreValue(key, "parent")

	branch := NewContext(new(dns.Msg).SetQuestion("branch.example.", dns.TypeA))
	branch.SetMark(8)
	branch.StoreValue(key, "branch")
	branch.SetResponse(new(dns.Msg).SetReply(branch.Q()))
	parent.CommitResponse(branch.SnapshotResponse())
	if !parent.HasMark(7) || parent.HasMark(8) {
		t.Fatal("legacy response-only commit changed marks")
	}
	if got, _ := parent.GetValue(key); got != "parent" {
		t.Fatal("legacy response-only commit changed KV")
	}

	parent.CommitResponse(ResponseSnapshot{}, CommitMerge)
	if !parent.HasMark(7) {
		t.Fatal("empty merge erased parent marks")
	}
	if got, _ := parent.GetValue(key); got != "parent" {
		t.Fatal("empty merge erased parent KV")
	}

	parent.CommitResponse(ResponseSnapshot{}, CommitReplace)
	if parent.HasMark(7) {
		t.Fatal("empty replacement did not remove parent marks")
	}
	if _, ok := parent.GetValue(key); ok {
		t.Fatal("empty replacement did not remove parent KV")
	}
}
