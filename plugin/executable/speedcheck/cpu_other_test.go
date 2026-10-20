//go:build !windows && !linux

package speedcheck

import "time"

func processCPUTime() (time.Duration, bool) { return 0, false }
