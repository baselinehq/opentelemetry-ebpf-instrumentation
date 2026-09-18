// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goversion"
)

func TestExtractCompleteRuntimeABI(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "inspect")
	source := filepath.Join("..", "..", "configs", "offsets", "std_inspect.go")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", executable, source)
	cmd.Env = append(os.Environ(), "GOOS=linux")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	info, err := buildinfo.ReadFile(executable)
	require.NoError(t, err)
	targetVersion, err := goversion.Parse(info.GoVersion)
	require.NoError(t, err)

	file, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	data, err := file.DWARF()
	require.NoError(t, err)

	abi, err := Extract(data, targetVersion)
	require.NoError(t, err)
	assertUnfilteredDWARFFacts(t, data, targetVersion, abi)
	requirements, err := Requirements(targetVersion)
	require.NoError(t, err)
	assert.Len(t, abi.Facts(), len(requirements))
	if targetVersion.Compare(go127) < 0 {
		assert.Nil(t, abi.TypeMetadata)
		return
	}
	require.NotNil(t, abi.TypeMetadata)
	assert.Equal(t, uint64(0), abi.TypeMetadata.ITabInterOffset)

	legacyABI, err := Extract(data, goversion.MustParse("go1.26.9"))
	require.NoError(t, err)
	assert.Nil(t, legacyABI.TypeMetadata)
	assert.Len(t, legacyABI.Facts(), 6)
}

func TestStoreValueRejectsConflicts(t *testing.T) {
	values := map[string]uint64{"fact": 1}
	require.NoError(t, storeValue(values, "fact", 1))
	require.ErrorContains(t, storeValue(values, "fact", 2), "conflicting values")
}

// Compare scoped discovery with a full traversal so linker placement changes
// cannot silently hide runtime types or constants in another compilation unit.
func assertUnfilteredDWARFFacts(t *testing.T, data *dwarf.Data, version goversion.Version, actual ABI) {
	t.Helper()
	definitions, err := requiredDefinitions(version)
	require.NoError(t, err)
	queries := map[string][]definition{}
	for _, definition := range definitions {
		name := definition.query.name()
		queries[name] = append(queries[name], definition)
	}
	facts := map[string]uint64{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		require.NoError(t, err)
		if entry == nil {
			break
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		for _, definition := range queries[name] {
			value, found, err := definition.query.extract(data, entry)
			require.NoError(t, err)
			if found {
				require.NoError(t, storeValue(facts, definition.Key(), value))
			}
		}
	}
	actualFacts := map[string]uint64{}
	for _, fact := range actual.Facts() {
		actualFacts[fact.Requirement.Key()] = fact.Value
	}
	require.Equal(t, facts, actualFacts)
}
