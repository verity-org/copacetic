package bulk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagExistsInRepo(t *testing.T) {
	tests := []struct {
		name     string
		repo     string
		tag      string
		allTags  []string
		expected bool
	}{
		{
			name:     "tag exists",
			repo:     "registry.io/nginx",
			tag:      "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.3-patched", "latest"},
			expected: true,
		},
		{
			name:     "tag does not exist",
			repo:     "registry.io/nginx",
			tag:      "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.2-patched", "latest"},
			expected: false,
		},
		{
			name:     "empty tag list",
			repo:     "registry.io/nginx",
			tag:      "1.25.3-patched",
			allTags:  []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldListAllTags := listAllTags
			defer func() { listAllTags = oldListAllTags }()
			listAllTags = func(repo name.Repository) ([]string, error) {
				return tt.allTags, nil
			}

			exists, err := tagExistsInRepo(tt.repo, tt.tag)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, exists)
		})
	}
}

func TestTagExistsInRepo_RegistryError(t *testing.T) {
	oldListAllTags := listAllTags
	defer func() { listAllTags = oldListAllTags }()
	listAllTags = func(repo name.Repository) ([]string, error) {
		return nil, fmt.Errorf("registry auth failed")
	}

	exists, err := tagExistsInRepo("registry.io/nginx", "1.25.3-patched")
	// Should fail-open: no error, tag treated as not existing
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestCheckReportForVulnerabilities(t *testing.T) {
	t.Run("function signature", func(t *testing.T) {
		// Verify the function is callable
		assert.NotNil(t, checkReportForVulnerabilities)
	})
}

func TestBuildReportIndex(t *testing.T) {
	// Create a temporary directory for test reports
	tmpDir := t.TempDir()

	// Create test report files
	report1 := `{"ArtifactName": "alpine:3.14.0", "Results": []}`
	report2 := `{"ArtifactName": "registry.io/nginx:1.25.3-patched", "Results": []}`
	report3 := `{"ArtifactName": "quay.io/prometheus/alertmanager:v0.28.1", "Results": []}`
	invalidJSON := `{invalid json`
	noArtifact := `{"Results": []}`

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "alpine.json"), []byte(report1), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nginx.json"), []byte(report2), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "prometheus.json"), []byte(report3), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.json"), []byte(invalidJSON), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "no-artifact.json"), []byte(noArtifact), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "not-json.txt"), []byte("text file"), 0o600))

	// Build the index
	idx := buildReportIndex(tmpDir)

	// Verify the index was built correctly
	assert.NotNil(t, idx)
	assert.NotNil(t, idx.refs)

	// Check that valid reports were indexed (3 valid reports)
	assert.Equal(t, 3, len(idx.refs), "Should index 3 valid reports")

	// Verify specific entries (normalized references)
	_, found := idx.refs["index.docker.io/library/alpine:3.14.0"]
	assert.True(t, found, "Should find alpine report")

	_, found = idx.refs["registry.io/nginx:1.25.3-patched"]
	assert.True(t, found, "Should find nginx report")

	_, found = idx.refs["quay.io/prometheus/alertmanager:v0.28.1"]
	assert.True(t, found, "Should find prometheus report")

	// Verify invalid files were not indexed
	assert.Equal(t, 3, len(idx.refs), "Should only have 3 entries (invalid files skipped)")
}

func TestReportIndexLookup(t *testing.T) {
	tests := []struct {
		name        string
		indexRefs   map[string]string
		lookupRef   string
		expectFound bool
		expectPath  string
	}{
		{
			name: "exact match",
			indexRefs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/nginx.json",
			},
			lookupRef:   "registry.io/nginx:1.25.3-patched",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "short form lookup matches normalized docker.io",
			indexRefs: map[string]string{
				"index.docker.io/library/nginx:1.25.3": "/tmp/reports/nginx.json",
			},
			lookupRef:   "nginx:1.25.3",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "full docker.io matches short form",
			indexRefs: map[string]string{
				"index.docker.io/library/nginx:1.25.3": "/tmp/reports/nginx.json",
			},
			lookupRef:   "docker.io/library/nginx:1.25.3",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "custom registry exact match",
			indexRefs: map[string]string{
				"quay.io/prometheus/alertmanager:v0.28.1": "/tmp/reports/alertmanager.json",
			},
			lookupRef:   "quay.io/prometheus/alertmanager:v0.28.1",
			expectFound: true,
			expectPath:  "/tmp/reports/alertmanager.json",
		},
		{
			name: "not found in index",
			indexRefs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/nginx.json",
			},
			lookupRef:   "registry.io/alpine:3.19",
			expectFound: false,
		},
		{
			name:        "nil index",
			indexRefs:   nil,
			lookupRef:   "nginx:1.25.3",
			expectFound: false,
		},
		{
			name:        "empty index",
			indexRefs:   map[string]string{},
			lookupRef:   "nginx:1.25.3",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var idx *reportIndex
			if tt.indexRefs != nil {
				idx = &reportIndex{refs: tt.indexRefs}
			}

			path, found := idx.lookup(tt.lookupRef)

			assert.Equal(t, tt.expectFound, found, "Found mismatch")
			if tt.expectFound {
				assert.Equal(t, tt.expectPath, path, "Path mismatch")
			}
		})
	}
}

func TestEvaluatePatchAction(t *testing.T) {
	tests := []struct {
		name             string
		repo             string
		baseTag          string
		scanner          string
		reports          *reportIndex
		existingTags     []string
		reportResult     bool // true = has vulns, false = no vulns
		reportError      error
		listTagsError    error
		expectedSkip     bool
		expectedReason   string
		expectedResolved string
	}{
		{
			name:             "no existing patched tags",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}},
			existingTags:     []string{},
			expectedSkip:     false,
			expectedReason:   "not_patched",
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "existing tag, no vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     false, // no vulns
			expectedSkip:     true,
			expectedReason:   "no fixable vulnerabilities",
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "existing tag, has vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     true, // has vulns
			expectedSkip:     false,
			expectedReason:   "new_vulnerabilities",
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "existing tag, report parse error",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportError:      fmt.Errorf("invalid JSON"),
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched",
		},
		{
			name:             "existing tag, report not found in index",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}}, // empty index
			existingTags:     []string{"1.25.3-patched"},
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched",
		},
		{
			name:             "registry tag listing fails",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}},
			listTagsError:    fmt.Errorf("auth error"),
			expectedSkip:     false,
			expectedReason:   "not_patched",
			expectedResolved: "1.25.3-patched",
		},
		{
			name:             "no reports index provided",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          nil, // nil index
			existingTags:     []string{"1.25.3-patched"},
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "custom scanner supported",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "native",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     false,
			expectedSkip:     true,
			expectedReason:   "no fixable vulnerabilities",
			expectedResolved: "1.25.3-patched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock listAllTags
			oldListAllTags := listAllTags
			defer func() { listAllTags = oldListAllTags }()
			listAllTags = func(repo name.Repository) ([]string, error) {
				if tt.listTagsError != nil {
					return nil, tt.listTagsError
				}
				// Return the existing tags plus some unrelated tags
				allTags := append([]string{"latest", "1.25.2"}, tt.existingTags...)
				return allTags, nil
			}

			// Mock checkReportForVulnerabilities
			oldCheck := checkReportForVulnerabilities
			defer func() { checkReportForVulnerabilities = oldCheck }()
			checkCalled := false
			checkReportForVulnerabilities = func(reportPath, scanner, pkgTypes, libraryPatchLevel string) (bool, error) {
				checkCalled = true
				if tt.reportError != nil {
					return false, tt.reportError
				}
				return tt.reportResult, nil
			}

			result := evaluatePatchAction(tt.repo, tt.baseTag, tt.scanner, tt.reports, "os", "patch")

			assert.Equal(t, tt.expectedSkip, result.ShouldSkip, "ShouldSkip mismatch")
			assert.Equal(t, tt.expectedReason, result.Reason, "Reason mismatch")
			assert.Equal(t, tt.expectedResolved, result.ResolvedTag, "ResolvedTag mismatch")

			// Verify check was only called when expected
			if len(tt.existingTags) == 0 || tt.reports == nil || tt.listTagsError != nil {
				assert.False(t, checkCalled, "Report check should not have been called")
			} else {
				// Check was called only if report was found in the index
				imageRef := fmt.Sprintf("%s:%s", tt.repo, tt.baseTag)
				_, found := tt.reports.lookup(imageRef)
				assert.Equal(t, found, checkCalled, "Report check call mismatch")
			}
		})
	}
}
