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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogConfig struct {
	// Level, See also zapcore.ParseLevel.
	Level string `yaml:"level"`

	// File that logger will be writen into.
	// Default is stderr.
	File string `yaml:"file"`

	// Production enables json output.
	Production bool `yaml:"production"`

	// Size limits the active file; K/M/G/T use binary units, and no unit means M.
	// The historical OpenWrt patches default this limit to 5M.
	Size string `yaml:"size"`

	// Backups limits retained rotated files. Zero keeps none; negative keeps all.
	Backups int `yaml:"backups"`
}

var (
	stderr = zapcore.Lock(os.Stderr)
	lvl    = zap.NewAtomicLevelAt(zap.InfoLevel)
	l      = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), stderr, lvl))
	s      = l.Sugar()

	nop = zap.NewNop()
)

func NewLogger(lc LogConfig) (*zap.Logger, error) {
	logger, _, err := NewLoggerWithCleanup(lc)
	return logger, err
}

// NewLoggerWithCleanup also returns ownership of any opened log file.
// Cleanup is idempotent and must run after the last log entry is written.
func NewLoggerWithCleanup(lc LogConfig) (*zap.Logger, func(), error) {
	lvl, err := zapcore.ParseLevel(lc.Level)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid log level: %w", err)
	}

	var out zapcore.WriteSyncer
	closeOutput := func() {}
	if lf := lc.File; len(lf) > 0 {
		if filename, ok := rotatingFilePath(lf); ok {
			maxSize, err := ParseSize(lc.Size)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid log size limit: %w", err)
			}
			r := &Rotator{Filename: filename, MaxSize: maxSize, MaxBackups: lc.Backups}
			if err := r.open(); err != nil {
				return nil, nil, fmt.Errorf("open log file: %w", err)
			}
			out = zapcore.AddSync(r)
			closeOutput = func() { _ = r.Close() }
		} else {
			// Preserve zap's stdout/stderr and registered URL sinks, including
			// their close ownership, rather than treating a URL as a filename.
			f, closeFile, err := zap.Open(lf)
			if err != nil {
				return nil, nil, fmt.Errorf("open log file: %w", err)
			}
			out = zapcore.Lock(f)
			closeOutput = closeFile
		}
	} else {
		out = stderr
	}

	var encoder zapcore.Encoder
	if lc.Production {
		config := zap.NewProductionEncoderConfig()
		config.EncodeTime = encodeLogTime
		encoder = zapcore.NewJSONEncoder(config)
	} else {
		config := zap.NewDevelopmentEncoderConfig()
		config.EncodeTime = encodeLogTime
		encoder = zapcore.NewConsoleEncoder(config)
	}
	logger := zap.New(zapcore.NewCore(encoder, out, lvl))
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = logger.Sync()
			closeOutput()
		})
	}
	return logger, cleanup, nil
}

func encodeLogTime(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05"))
}

func rotatingFilePath(path string) (string, bool) {
	if path == "stdout" || path == "stderr" {
		return "", false
	}
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return path, true
	}
	u, err := url.Parse(path)
	if err != nil {
		return "", false
	}
	if u.Scheme == "" && u.RawQuery == "" && u.Fragment == "" {
		return path, true
	}
	if u.Scheme == "file" && (u.Host == "" || u.Host == "localhost") && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		return u.Path, true
	}
	return "", false
}

// L is a global logger.
func L() *zap.Logger {
	return l
}

// SetLevel sets the log level for the global logger.
func SetLevel(l zapcore.Level) {
	lvl.SetLevel(l)
}

// S is a global logger.
func S() *zap.SugaredLogger {
	return s
}

// Nop is a logger that never writes out logs.
func Nop() *zap.Logger {
	return nop
}
