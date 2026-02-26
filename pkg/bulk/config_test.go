package bulk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTagStrategy_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		name      string
		yamlInput string
		expectErr bool
		checkFunc func(*TagStrategy) bool // Optional check for successful unmarshals
	}{
		{
			name: "Valid Strategy - List",
			yamlInput: `
strategy: "list"
list: ["tag1", "tag2"]`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "list" && len(ts.List) == 2
			},
		},
		{
			name: "Invalid Strategy - List without items",
			yamlInput: `strategy: "list"
									list: []`,
			expectErr: true,
		},
		{
			name: "Valid Strategy - Pattern",
			yamlInput: `
strategy: "pattern"
pattern: "^1\\.2[0-9]+$"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "pattern" && ts.compiledPattern != nil
			},
		},
		{
			name:      "Invalid Strategy - Pattern without pattern string",
			yamlInput: `strategy: "pattern"`,
			expectErr: true,
		},
		{
			name: "Invalid Strategy - Pattern with bad regex",
			yamlInput: `strategy: "pattern"
									pattern: "*not-a-valid-regex"`,
			expectErr: true,
		},
		{
			name:      "Valid Strategy - Latest",
			yamlInput: `strategy: "latest"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "latest"
			},
		},
		{
			name:      "Invalid Strategy - Unknown",
			yamlInput: `strategy: "unknown"`,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ts TagStrategy
			err := yaml.Unmarshal([]byte(tc.yamlInput), &ts)

			if (err != nil) != tc.expectErr {
				t.Errorf("Expected error: %v, but got: %v", tc.expectErr, err)
			}

			if !tc.expectErr && tc.checkFunc != nil {
				if !tc.checkFunc(&ts) {
					t.Errorf("Post-unmarshal check failed for valid case")
				}
			}
		})
	}
}

func TestValidateCharts(t *testing.T) {
	tests := []struct {
		name      string
		charts    []ChartSpec
		expectErr string
	}{
		{
			name:      "empty charts is valid",
			charts:    nil,
			expectErr: "",
		},
		{
			name: "valid OCI chart",
			charts: []ChartSpec{
				{Name: "prometheus", Version: "28.9.1", Repository: "oci://ghcr.io/prometheus-community/charts"},
			},
			expectErr: "",
		},
		{
			name: "valid HTTPS chart",
			charts: []ChartSpec{
				{Name: "victoria-logs-single", Version: "0.11.26", Repository: "https://victoriametrics.github.io/helm-charts"},
			},
			expectErr: "",
		},
		{
			name: "missing name",
			charts: []ChartSpec{
				{Version: "1.0.0", Repository: "oci://ghcr.io/charts"},
			},
			expectErr: "name is required",
		},
		{
			name: "missing version",
			charts: []ChartSpec{
				{Name: "mychart", Repository: "oci://ghcr.io/charts"},
			},
			expectErr: "version is required",
		},
		{
			name: "missing repository",
			charts: []ChartSpec{
				{Name: "mychart", Version: "1.0.0"},
			},
			expectErr: "repository is required",
		},
		{
			name: "invalid repository scheme",
			charts: []ChartSpec{
				{Name: "mychart", Version: "1.0.0", Repository: "http://insecure.example.com/charts"},
			},
			expectErr: "repository must start with 'oci://' or 'https://'",
		},
		{
			name: "second chart invalid",
			charts: []ChartSpec{
				{Name: "good", Version: "1.0.0", Repository: "oci://registry.io/charts"},
				{Name: "bad", Version: "1.0.0", Repository: "ftp://bad.example.com"},
			},
			expectErr: "repository must start with",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCharts(tt.charts)
			if tt.expectErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			}
		})
	}
}

func TestValidateOverrides(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]OverrideSpec
		expectErr string
	}{
		{
			name:      "nil overrides is valid",
			overrides: nil,
			expectErr: "",
		},
		{
			name: "valid override",
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
			},
			expectErr: "",
		},
		{
			name: "missing from",
			overrides: map[string]OverrideSpec{
				"timberio/vector": {To: "debian"},
			},
			expectErr: "from is required",
		},
		{
			name: "missing to",
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc"},
			},
			expectErr: "to is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOverrides(tt.overrides)
			if tt.expectErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			}
		})
	}
}

func TestPatchConfig_UnmarshalYAML_Charts(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		expectErr bool
		check     func(t *testing.T, cfg PatchConfig)
	}{
		{
			name: "backward compatibility - images only",
			yaml: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
images:
  - name: nginx
    image: docker.io/library/nginx
    tags:
      strategy: list
      list: ["1.25.0"]
`,
			check: func(t *testing.T, cfg PatchConfig) {
				assert.Len(t, cfg.Images, 1)
				assert.Empty(t, cfg.Charts)
				assert.Empty(t, cfg.Overrides)
			},
		},
		{
			name: "charts section parsed correctly",
			yaml: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
charts:
  - name: prometheus
    version: "28.9.1"
    repository: "oci://ghcr.io/prometheus-community/charts"
  - name: victoria-logs-single
    version: "0.11.26"
    repository: "https://victoriametrics.github.io/helm-charts"
`,
			check: func(t *testing.T, cfg PatchConfig) {
				require.Len(t, cfg.Charts, 2)
				assert.Equal(t, "prometheus", cfg.Charts[0].Name)
				assert.Equal(t, "28.9.1", cfg.Charts[0].Version)
				assert.Equal(t, "oci://ghcr.io/prometheus-community/charts", cfg.Charts[0].Repository)
				assert.Equal(t, "victoria-logs-single", cfg.Charts[1].Name)
				assert.Empty(t, cfg.Images)
			},
		},
		{
			name: "overrides section parsed correctly",
			yaml: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
overrides:
  timberio/vector:
    from: "distroless-libc"
    to: "debian"
charts:
  - name: mychart
    version: "1.0.0"
    repository: "oci://ghcr.io/charts"
`,
			check: func(t *testing.T, cfg PatchConfig) {
				require.Len(t, cfg.Overrides, 1)
				o := cfg.Overrides["timberio/vector"]
				assert.Equal(t, "distroless-libc", o.From)
				assert.Equal(t, "debian", o.To)
			},
		},
		{
			name: "charts and images together",
			yaml: `
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
charts:
  - name: mychart
    version: "1.0.0"
    repository: "oci://ghcr.io/charts"
images:
  - name: nginx
    image: docker.io/library/nginx
    tags:
      strategy: list
      list: ["1.25.0"]
`,
			check: func(t *testing.T, cfg PatchConfig) {
				assert.Len(t, cfg.Charts, 1)
				assert.Len(t, cfg.Images, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg PatchConfig
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, cfg)
				}
			}
		})
	}
}
