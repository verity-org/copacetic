package bulk

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/project-copacetic/copacetic/pkg/helm"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	helmchart "helm.sh/helm/v3/pkg/chart"
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

func TestPatchFromConfig_DryRun(t *testing.T) {
	// Dry-run must not invoke patch.Patch; it records "WouldPatch" for every
	// image that skip-detection would not skip.
	origListAllTags := listAllTags
	t.Cleanup(func() { listAllTags = origListAllTags })
	// No existing patched tags → skip detection says "not_patched" → WouldPatch
	listAllTags = func(_ name.Repository) ([]string, error) {
		return []string{}, nil
	}

	configContent := `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: registry.io/myorg
  tag: "{{ .SourceTag }}-patched"
images:
  - name: nginx
    image: docker.io/library/nginx
    tags:
      strategy: list
      list: ["1.25.0", "1.26.0"]
  - name: redis
    image: docker.io/library/redis
    tags:
      strategy: list
      list: ["7.0"]
`
	configPath := filepath.Join(t.TempDir(), "copa-config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

	outputPath := filepath.Join(t.TempDir(), "results.json")

	opts := &types.Options{
		DryRun:            true,
		Scanner:           "trivy",
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
		OutputJSON:        outputPath,
	}

	err := PatchFromConfig(context.Background(), configPath, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var results []patchJobResult
	require.NoError(t, json.Unmarshal(data, &results))

	require.Len(t, results, 3)
	for _, r := range results {
		assert.Equal(t, "WouldPatch", r.Status)
		assert.Empty(t, r.Error)
	}

	// Verify source/target format
	sources := make(map[string]string)
	for _, r := range results {
		sources[r.Source] = r.Target
	}
	assert.Equal(t, "registry.io/myorg/nginx:1.25.0-patched", sources["docker.io/library/nginx:1.25.0"])
	assert.Equal(t, "registry.io/myorg/nginx:1.26.0-patched", sources["docker.io/library/nginx:1.26.0"])
	assert.Equal(t, "registry.io/myorg/redis:7.0-patched", sources["docker.io/library/redis:7.0"])
}

func TestPatchFromConfig_DryRun_SkipsAlreadyPatched(t *testing.T) {
	origListAllTags := listAllTags
	t.Cleanup(func() { listAllTags = origListAllTags })
	// Return an existing patched tag
	listAllTags = func(_ name.Repository) ([]string, error) {
		return []string{"1.25.0-patched"}, nil
	}

	origCheckReport := checkReportForVulnerabilities
	t.Cleanup(func() { checkReportForVulnerabilities = origCheckReport })
	// No vulnerabilities → skip
	checkReportForVulnerabilities = func(_, _, _, _ string) (bool, error) {
		return false, nil
	}

	reportsDir := t.TempDir()
	reportJSON := `{"ArtifactName": "registry.io/myorg/nginx:1.25.0-patched"}`
	require.NoError(t, os.WriteFile(filepath.Join(reportsDir, "report.json"), []byte(reportJSON), 0o600))

	configContent := `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: registry.io/myorg
  tag: "{{ .SourceTag }}-patched"
images:
  - name: nginx
    image: docker.io/library/nginx
    tags:
      strategy: list
      list: ["1.25.0"]
`
	configPath := filepath.Join(t.TempDir(), "copa-config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

	outputPath := filepath.Join(t.TempDir(), "results.json")

	opts := &types.Options{
		DryRun:            true,
		Scanner:           "trivy",
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
		Report:            reportsDir,
		OutputJSON:        outputPath,
	}

	err := PatchFromConfig(context.Background(), configPath, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var results []patchJobResult
	require.NoError(t, json.Unmarshal(data, &results))

	// Image is already patched with no new vulns → Skipped, not WouldPatch
	require.Len(t, results, 1)
	assert.Equal(t, "Skipped", results[0].Status)
	assert.Equal(t, "no fixable vulnerabilities", results[0].Details)
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

func TestMergeImageSpecs(t *testing.T) {
	baseConfig := PatchConfig{
		APIVersion: ExpectedAPIVersion,
		Kind:       ExpectedKind,
		Target:     TargetSpec{Registry: "ghcr.io/org"},
	}

	tests := []struct {
		name        string
		explicit    []ImageSpec
		chartImages []ImageSpec
		wantImages  []string // expected image repositories in result
	}{
		{
			name:        "chart images added when no explicit images",
			explicit:    nil,
			chartImages: []ImageSpec{{Name: "redis", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}}}},
			wantImages:  []string{"redis"},
		},
		{
			name: "chart images added alongside explicit images",
			explicit: []ImageSpec{
				{Name: "nginx", Image: "docker.io/library/nginx", Tags: TagStrategy{Strategy: StrategyList, List: []string{"1.25"}}},
			},
			chartImages: []ImageSpec{
				{Name: "redis", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}}},
			},
			wantImages: []string{"docker.io/library/nginx", "redis"},
		},
		{
			name: "explicit image takes precedence over chart image with same repo",
			explicit: []ImageSpec{
				{Name: "nginx-explicit", Image: "docker.io/library/nginx", Tags: TagStrategy{Strategy: StrategyList, List: []string{"1.26"}}},
			},
			chartImages: []ImageSpec{
				{Name: "nginx-chart", Image: "docker.io/library/nginx", Tags: TagStrategy{Strategy: StrategyList, List: []string{"1.25"}}},
			},
			wantImages: []string{"docker.io/library/nginx"},
		},
		{
			name:     "chart-to-chart deduplication",
			explicit: nil,
			chartImages: []ImageSpec{
				{Name: "redis-a", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}}},
				{Name: "redis-b", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}}},
			},
			wantImages: []string{"redis"},
		},
		{
			name:        "no chart images returns only explicit",
			explicit:    []ImageSpec{{Name: "nginx", Image: "nginx", Tags: TagStrategy{Strategy: StrategyList, List: []string{"1.25"}}}},
			chartImages: nil,
			wantImages:  []string{"nginx"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig
			cfg.Images = tt.explicit
			result := mergeImageSpecs(cfg, tt.chartImages)

			gotImages := make([]string, len(result.Images))
			for i, img := range result.Images {
				gotImages[i] = img.Image
			}
			assert.ElementsMatch(t, tt.wantImages, gotImages)

			// Immutability: original config.Images must not be modified
			assert.Equal(t, tt.explicit, cfg.Images)
		})
	}
}

func TestChartImagesToSpecs(t *testing.T) {
	images := []helm.ChartImage{
		{Repository: "docker.io/nginx", Tag: "1.25.0"},
		{Repository: "redis", Tag: "7.0"},
	}

	specs := chartImagesToSpecs(images)

	require.Len(t, specs, 2)
	assert.Equal(t, "docker.io/nginx", specs[0].Image)
	assert.Equal(t, "docker.io/nginx", specs[0].Name)
	assert.Equal(t, StrategyList, specs[0].Tags.Strategy)
	assert.Equal(t, []string{"1.25.0"}, specs[0].Tags.List)

	assert.Equal(t, "redis", specs[1].Image)
	assert.Equal(t, []string{"7.0"}, specs[1].Tags.List)
}

func TestToHelmOverrides(t *testing.T) {
	overrides := map[string]OverrideSpec{
		"timberio/vector": {From: "distroless-libc", To: "debian"},
	}
	result := toHelmOverrides(overrides)
	require.Len(t, result, 1)
	assert.Equal(t, "distroless-libc", result["timberio/vector"].From)
	assert.Equal(t, "debian", result["timberio/vector"].To)

	assert.Nil(t, toHelmOverrides(nil))
}

func TestPatchFromConfig_DryRun_WithCharts(t *testing.T) {
	// Mock chart download and render to avoid network access
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
		}, nil
	}

	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: redis:7.0
`, nil
	}

	origListAllTags := listAllTags
	t.Cleanup(func() { listAllTags = origListAllTags })
	listAllTags = func(_ name.Repository) ([]string, error) {
		return []string{}, nil
	}

	configContent := `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: registry.io/myorg
charts:
  - name: mychart
    version: "1.0.0"
    repository: "oci://ghcr.io/charts"
`
	configPath := filepath.Join(t.TempDir(), "copa-config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

	outputPath := filepath.Join(t.TempDir(), "results.json")
	opts := &types.Options{
		DryRun:            true,
		Scanner:           "trivy",
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
		OutputJSON:        outputPath,
	}

	err := PatchFromConfig(context.Background(), configPath, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var results []patchJobResult
	require.NoError(t, json.Unmarshal(data, &results))

	require.Len(t, results, 1)
	assert.Equal(t, "WouldPatch", results[0].Status)
	assert.Equal(t, "redis:7.0", results[0].Source)
	assert.Equal(t, "registry.io/myorg/redis:7.0-patched", results[0].Target)
}

func TestPatchFromConfig_DryRun_ChartsAndImages_Dedup(t *testing.T) {
	// Chart discovers nginx:1.25.0, but explicit images list also has nginx — explicit wins.
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{Metadata: &helmchart.Metadata{Name: name, Version: version}}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: docker.io/library/nginx:1.25.0
        - image: redis:7.0
`, nil
	}

	origListAllTags := listAllTags
	t.Cleanup(func() { listAllTags = origListAllTags })
	listAllTags = func(_ name.Repository) ([]string, error) { return []string{}, nil }

	configContent := `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
target:
  registry: registry.io/myorg
charts:
  - name: mychart
    version: "1.0.0"
    repository: "oci://ghcr.io/charts"
images:
  - name: nginx-explicit
    image: docker.io/library/nginx
    tags:
      strategy: list
      list: ["1.26.0"]
`
	configPath := filepath.Join(t.TempDir(), "copa-config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

	outputPath := filepath.Join(t.TempDir(), "results.json")
	opts := &types.Options{
		DryRun:            true,
		Scanner:           "trivy",
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
		OutputJSON:        outputPath,
	}

	err := PatchFromConfig(context.Background(), configPath, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var results []patchJobResult
	require.NoError(t, json.Unmarshal(data, &results))

	// Should have 2 jobs: nginx:1.26.0 (explicit wins over chart's 1.25.0) + redis:7.0
	require.Len(t, results, 2)

	sources := make(map[string]string)
	for _, r := range results {
		sources[r.Source] = r.Target
	}
	// Explicit nginx:1.26.0 should be present, not chart's 1.25.0
	assert.Contains(t, sources, "docker.io/library/nginx:1.26.0")
	assert.NotContains(t, sources, "docker.io/library/nginx:1.25.0")
	// Redis from chart should be present
	assert.Contains(t, sources, "redis:7.0")
}

func TestPatchFromConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name          string
		configContent string
		wantErrSubstr string
	}{
		{
			name: "empty config (no charts, no images)",
			configContent: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
`,
			wantErrSubstr: "at least one chart or image",
		},
		{
			name: "chart with invalid repository scheme",
			configContent: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
charts:
  - name: mychart
    version: "1.0.0"
    repository: "http://insecure.example.com"
`,
			wantErrSubstr: "repository must start with",
		},
		{
			name: "override with empty from",
			configContent: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
overrides:
  myimage:
    from: ""
    to: "debian"
images:
  - name: nginx
    image: nginx
    tags:
      strategy: list
      list: ["1.25"]
`,
			wantErrSubstr: "from is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "copa-config.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte(tt.configContent), 0o600))

			opts := &types.Options{DryRun: true, Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch"}
			err := PatchFromConfig(context.Background(), configPath, opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrSubstr)
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
