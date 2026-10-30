/*
 * Copyright (C) 2020-2022, IrineSistiana
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

package mlog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Rotator struct {
	Filename   string
	MaxSize    int64
	MaxBackups int

	size         int64
	f            *os.File
	mu           sync.Mutex
	closed       bool
	lastRotation time.Time
}

func (r *Rotator) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}

	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}

	// A log may be externally truncated. Windows O_APPEND alone does not
	// always reset the old file pointer; seek to the actual end before writing.
	info, err := r.f.Stat()
	if err != nil {
		return 0, err
	}
	r.size = info.Size()
	if _, err := r.f.Seek(0, io.SeekEnd); err != nil {
		return 0, err
	}
	writeLen := int64(len(p))
	if r.MaxSize > 0 && r.size+writeLen > r.MaxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err = r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotator) open() error {
	info, err := os.Stat(r.Filename)
	if os.IsNotExist(err) {
		return r.openNew()
	}
	if err != nil {
		return err
	}
	r.size = info.Size()
	f, err := os.OpenFile(r.Filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsNotExist(err) {
			return r.openNew()
		}
		return err
	}
	r.f = f
	return nil
}

func (r *Rotator) openNew() error {
	err := os.MkdirAll(filepath.Dir(r.Filename), 0755)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.Filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *Rotator) rotate() error {
	if r.f != nil {
		if err := r.f.Close(); err != nil {
			return err
		}
		r.f = nil
	}
	_, err := os.Stat(r.Filename)
	if err == nil {
		ext := filepath.Ext(r.Filename)
		name := strings.TrimSuffix(r.Filename, ext)
		// Windows doesn't allow colons in filenames, so use dashes for time
		stamp := time.Now().Truncate(time.Millisecond)
		if !stamp.After(r.lastRotation) {
			stamp = r.lastRotation.Add(time.Millisecond)
		}
		var newName string
		for {
			newName = fmt.Sprintf("%s-%s%s", name, stamp.Format("2006-01-02T15-04-05.000"), ext)
			if _, err := os.Stat(newName); os.IsNotExist(err) {
				break
			} else if err != nil {
				return err
			}
			stamp = stamp.Add(time.Millisecond)
		}
		if err := os.Rename(r.Filename, newName); err != nil {
			// A failed rotation must never truncate the still-existing log.
			return err
		}
		r.lastRotation = stamp
	} else if !os.IsNotExist(err) {
		return err
	}
	err = r.openNew()
	if err == nil {
		r.cleanupBackups()
	}
	return err
}

func (r *Rotator) cleanupBackups() {
	if r.MaxBackups < 0 {
		return // < 0 means keep all
	}

	dir := filepath.Dir(r.Filename)
	ext := filepath.Ext(r.Filename)
	name := strings.TrimSuffix(filepath.Base(r.Filename), ext)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []string
	prefix := name + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		n := entry.Name()
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ext) {
			// Basic validation of the timestamp length
			timestamp := n[len(prefix) : len(n)-len(ext)]
			if len(timestamp) == 23 {
				backups = append(backups, filepath.Join(dir, n))
			}
		}
	}

	if len(backups) <= r.MaxBackups {
		return
	}

	// Sort alphabetically, which sorts by time since format is 2006-01-02T15-04-05.000
	sort.Strings(backups)

	toDelete := len(backups) - r.MaxBackups
	for i := 0; i < toDelete; i++ {
		os.Remove(backups[i])
	}
}

func (r *Rotator) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		return r.f.Sync()
	}
	return nil
}

func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f != nil {
		err := r.f.Close()
		r.f = nil
		return err
	}
	return nil
}

// ParseSize parses the size string and returns bytes.
// Supports K, M, G, T units. If no unit, defaults to M.
func ParseSize(s string) (int64, error) {
	if s == "" {
		return 5 * 1024 * 1024, nil // Default 5M
	}
	s = strings.ToUpper(strings.TrimSpace(s))

	var unit string
	var valStr string
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			valStr = s[:i]
			unit = s[i:]
			break
		}
	}
	if unit == "" {
		valStr = s
		unit = "M" // default to M
	}
	valStr = strings.TrimSpace(valStr)

	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return 0, err
	}

	switch unit {
	case "K", "KB":
		return val * 1024, nil
	case "M", "MB":
		return val * 1024 * 1024, nil
	case "G", "GB":
		return val * 1024 * 1024 * 1024, nil
	case "T", "TB":
		return val * 1024 * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid size unit: %s", unit)
	}
}
