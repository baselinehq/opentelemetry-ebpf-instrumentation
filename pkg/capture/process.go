// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func processStartTime(procFS string, pid uint32) string {
	b, err := os.ReadFile(filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return ""
	}
	// comm (field 2) is parenthesised and may contain spaces, so fields are
	// counted from after the closing ')'.
	close := strings.LastIndexByte(string(b), ')')
	if close < 0 {
		return ""
	}
	fields := strings.Fields(string(b)[close+1:])
	// after ')' the next field is state (3), so start time (22) is index 19
	const startTimeOffset = 19
	if len(fields) <= startTimeOffset {
		return ""
	}
	return fields[startTimeOffset]
}
