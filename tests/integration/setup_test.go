package integration_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/IrineSistiana/mosdns/v5/plugin"
)

// Integration fixtures use the same working-directory-relative paths as the
// deployed configs. Set only this test process's directory to the module root.
func TestMain(m *testing.M) {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration tests: get working directory:", err)
		os.Exit(1)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			if err := os.Chdir(dir); err != nil {
				fmt.Fprintln(os.Stderr, "integration tests: set module root:", err)
				os.Exit(1)
			}
			os.Exit(m.Run())
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fmt.Fprintln(os.Stderr, "integration tests: could not find module root")
			os.Exit(1)
		}
		dir = parent
	}
}
