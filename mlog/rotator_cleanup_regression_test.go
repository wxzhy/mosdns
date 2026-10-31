package mlog

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCleanupBackupsIgnoresUnrelatedSameLengthName(t *testing.T) {
 dir := t.TempDir()
 other := filepath.Join(dir, "app-"+strings.Repeat("x", 23)+".log")
 if err := os.WriteFile(other, []byte("keep"), 0600); err != nil { t.Fatal(err) }
 r := &Rotator{Filename: filepath.Join(dir, "app.log"), MaxSize: 2, MaxBackups: 0}
 defer r.Close()
 if _, err := r.Write([]byte("ab")); err != nil { t.Fatal(err) }
 if _, err := r.Write([]byte("cd")); err != nil { t.Fatal(err) }
 if data, err := os.ReadFile(other); err != nil || string(data) != "keep" { t.Fatalf("unrelated file removed: %q, %v", data, err) }
}
