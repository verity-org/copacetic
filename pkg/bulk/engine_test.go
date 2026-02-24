package bulk

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSONResults(t *testing.T) {
	tests := []struct {
		name     string
		results  []patchJobStatus
		validate func(t *testing.T, got []patchJobResult)
	}{
		{
			name: "patched result with no error",
			results: []patchJobStatus{
				{Name: "nginx", Source: "nginx:1.25", Target: "ghcr.io/org/nginx:1.25-patched", Status: "Patched"},
			},
			validate: func(t *testing.T, got []patchJobResult) {
				require.Len(t, got, 1)
				assert.Equal(t, "nginx", got[0].Name)
				assert.Equal(t, "nginx:1.25", got[0].Source)
				assert.Equal(t, "ghcr.io/org/nginx:1.25-patched", got[0].Target)
				assert.Equal(t, "Patched", got[0].Status)
				assert.Empty(t, got[0].Error)
				assert.Empty(t, got[0].Details)
			},
		},
		{
			name: "failed result with error",
			results: []patchJobStatus{
				{Name: "redis", Source: "redis:7.0", Target: "N/A", Status: "Failed", Error: errors.New("patch failed: network timeout")},
			},
			validate: func(t *testing.T, got []patchJobResult) {
				require.Len(t, got, 1)
				assert.Equal(t, "Failed", got[0].Status)
				assert.Equal(t, "patch failed: network timeout", got[0].Error)
				assert.Empty(t, got[0].Details)
			},
		},
		{
			name: "skipped result with details",
			results: []patchJobStatus{
				{Name: "alpine", Source: "alpine:3.18", Target: "ghcr.io/org/alpine:3.18-patched", Status: "Skipped", Details: "no fixable vulnerabilities"},
			},
			validate: func(t *testing.T, got []patchJobResult) {
				require.Len(t, got, 1)
				assert.Equal(t, "Skipped", got[0].Status)
				assert.Equal(t, "no fixable vulnerabilities", got[0].Details)
				assert.Empty(t, got[0].Error)
			},
		},
		{
			name:    "empty results",
			results: []patchJobStatus{},
			validate: func(t *testing.T, got []patchJobResult) {
				assert.Empty(t, got)
			},
		},
		{
			name: "multiple results",
			results: []patchJobStatus{
				{Name: "nginx", Source: "nginx:1.25", Target: "ghcr.io/org/nginx:1.25-patched", Status: "Patched"},
				{Name: "redis", Source: "redis:7.0", Target: "N/A", Status: "Error", Error: errors.New("build failed")},
			},
			validate: func(t *testing.T, got []patchJobResult) {
				require.Len(t, got, 2)
				assert.Equal(t, "Patched", got[0].Status)
				assert.Equal(t, "Error", got[1].Status)
				assert.Equal(t, "build failed", got[1].Error)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "results.json")
			err := writeJSONResults(outPath, tt.results)
			require.NoError(t, err)

			data, err := os.ReadFile(outPath)
			require.NoError(t, err)

			var got []patchJobResult
			require.NoError(t, json.Unmarshal(data, &got))
			tt.validate(t, got)
		})
	}
}

func TestBuildTargetRepository(t *testing.T) {
	tests := []struct {
		name           string
		sourceImage    string
		targetRegistry string
		expected       string
		expectError    bool
	}{
		{
			name:           "empty target registry uses source",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "",
			expected:       "quay.io/opstree/redis",
			expectError:    false,
		},
		{
			name:           "target registry with namespace",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "docker.io library image",
			sourceImage:    "docker.io/library/nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "short form image",
			sourceImage:    "nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "multi-level namespace",
			sourceImage:    "registry.io/team/project/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "target registry with trailing slash",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg/",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "registry with port",
			sourceImage:    "registry.io:5000/team/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildTargetRepository(tt.sourceImage, tt.targetRegistry)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMergeTarget(t *testing.T) {
	tests := []struct {
		name         string
		globalTarget TargetSpec
		imageTarget  TargetSpec
		expected     TargetSpec
	}{
		{
			name:         "both empty",
			globalTarget: TargetSpec{},
			imageTarget:  TargetSpec{},
			expected:     TargetSpec{},
		},
		{
			name: "only global target",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name:         "only image target",
			globalTarget: TargetSpec{},
			imageTarget: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides global registry",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name: "image target overrides global tag",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Tag: "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides both",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeTarget(tt.globalTarget, tt.imageTarget)
			assert.Equal(t, tt.expected, result)
		})
	}
}
