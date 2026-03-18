package langmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveFromBinary(t *testing.T) {
	tests := []struct {
		name    string
		info    *GoBinaryInfo
		wantErr bool
		want    *GoSourceResolution
	}{
		{
			name: "binary with VCS info (Prometheus)",
			info: &GoBinaryInfo{
				Path:        "/bin/prometheus",
				MainModule:  "github.com/prometheus/prometheus",
				VCSRevision: "9ec59baffb54",
			},
			want: &GoSourceResolution{
				Repo:   "https://github.com/prometheus/prometheus",
				Ref:    "9ec59baffb54",
				Method: "binary-vcs",
			},
		},
		{
			name: "binary with VCS info and versioned module",
			info: &GoBinaryInfo{
				Path:        "/usr/bin/influxd",
				MainModule:  "github.com/influxdata/influxdb/v2",
				VCSRevision: "abc123",
			},
			want: &GoSourceResolution{
				Repo:   "https://github.com/influxdata/influxdb",
				Ref:    "abc123",
				Method: "binary-vcs",
			},
		},
		{
			name: "binary without VCS revision",
			info: &GoBinaryInfo{
				Path:       "/opt/cni/bin/calico",
				MainModule: "github.com/projectcalico/calico",
			},
			wantErr: true,
		},
		{
			name: "binary without module path",
			info: &GoBinaryInfo{
				Path:        "/configmap-reload",
				MainPath:    "command-line-arguments",
				MainModule:  "command-line-arguments",
				VCSRevision: "abc123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFromBinary(tt.info)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Repo, got.Repo)
			assert.Equal(t, tt.want.Ref, got.Ref)
			assert.Equal(t, "binary-vcs", got.Method)
		})
	}
}

func TestResolveFromTagHeuristic(t *testing.T) {
	tests := []struct {
		name     string
		info     *GoBinaryInfo
		imageRef string
		wantErr  bool
		want     *GoSourceResolution
	}{
		{
			name: "prometheus with version tag",
			info: &GoBinaryInfo{
				Path:       "/bin/prometheus",
				MainModule: "github.com/prometheus/prometheus",
			},
			imageRef: "quay.io/prometheus/prometheus:v3.9.1",
			want: &GoSourceResolution{
				Repo:   "https://github.com/prometheus/prometheus",
				Ref:    "v3.9.1",
				Method: "tag-heuristic",
			},
		},
		{
			name: "calico with version tag",
			info: &GoBinaryInfo{
				Path:       "/opt/cni/bin/calico",
				MainModule: "github.com/projectcalico/calico",
			},
			imageRef: "docker.io/calico/cni:v3.31.4",
			want: &GoSourceResolution{
				Repo:   "https://github.com/projectcalico/calico",
				Ref:    "v3.31.4",
				Method: "tag-heuristic",
			},
		},
		{
			name: "image with no tag",
			info: &GoBinaryInfo{
				Path:       "/bin/app",
				MainModule: "github.com/user/repo",
			},
			imageRef: "docker.io/user/app",
			wantErr:  true,
		},
		{
			name: "image with latest tag",
			info: &GoBinaryInfo{
				Path:       "/bin/app",
				MainModule: "github.com/user/repo",
			},
			imageRef: "docker.io/user/app:latest",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFromTagHeuristic(tt.info, tt.imageRef)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Repo, got.Repo)
			assert.Equal(t, tt.want.Ref, got.Ref)
			assert.Equal(t, "tag-heuristic", got.Method)
		})
	}
}

func TestResolveFromVCSOverride(t *testing.T) {
	tests := []struct {
		name     string
		vcsURL   string
		imageRef string
		wantErr  bool
		wantRepo string
		wantRef  string
	}{
		{
			name:     "repo@ref format",
			vcsURL:   "https://github.com/projectcalico/calico@v3.31.4",
			imageRef: "docker.io/calico/cni:v3.31.4",
			wantRepo: "https://github.com/projectcalico/calico",
			wantRef:  "v3.31.4",
		},
		{
			name:     "repo only, ref from image tag",
			vcsURL:   "https://github.com/hashicorp/vault",
			imageRef: "hashicorp/vault:1.21.3",
			wantRepo: "https://github.com/hashicorp/vault",
			wantRef:  "1.21.3",
		},
		{
			name:     "repo@commit-hash",
			vcsURL:   "https://github.com/org/repo@abc123def",
			imageRef: "image:v1",
			wantRepo: "https://github.com/org/repo",
			wantRef:  "abc123def",
		},
		{
			name:     "empty vcs url",
			vcsURL:   "",
			imageRef: "image:v1",
			wantErr:  true,
		},
		{
			name:     "repo only but image has no tag",
			vcsURL:   "https://github.com/org/repo",
			imageRef: "image",
			wantErr:  true,
		},
		{
			name:     "repo only but image tag is latest",
			vcsURL:   "https://github.com/org/repo",
			imageRef: "image:latest",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFromVCSOverride(tt.vcsURL, tt.imageRef)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepo, got.Repo)
			assert.Equal(t, tt.wantRef, got.Ref)
			assert.Equal(t, "vcs-override", got.Method)
		})
	}
}

func TestParseVCSURL(t *testing.T) {
	tests := []struct {
		input    string
		wantRepo string
		wantRef  string
	}{
		{"https://github.com/org/repo@v1.0.0", "https://github.com/org/repo", "v1.0.0"},
		{"https://github.com/org/repo@abc123", "https://github.com/org/repo", "abc123"},
		{"https://github.com/org/repo", "https://github.com/org/repo", ""},
		{"git@github.com:org/repo@v1.0", "git@github.com:org/repo", "v1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			repo, ref := parseVCSURL(tt.input)
			assert.Equal(t, tt.wantRepo, repo)
			assert.Equal(t, tt.wantRef, ref)
		})
	}
}

func TestResolveGoSource_FullChain(t *testing.T) {
	tests := []struct {
		name       string
		info       *GoBinaryInfo
		imageRef   string
		goVCSURL   string
		wantErr    bool
		wantMethod string
	}{
		{
			name: "step 1 wins: binary has VCS",
			info: &GoBinaryInfo{
				Path:        "/bin/prometheus",
				MainModule:  "github.com/prometheus/prometheus",
				VCSRevision: "abc123",
			},
			imageRef:   "quay.io/prometheus/prometheus:v3.9.1",
			goVCSURL:   "https://github.com/other/repo@v1.0",
			wantMethod: "binary-vcs",
		},
		{
			name: "step 2 wins: no VCS but tag available",
			info: &GoBinaryInfo{
				Path:       "/bin/app",
				MainModule: "github.com/user/repo",
			},
			imageRef:   "docker.io/user/app:v1.0.0",
			goVCSURL:   "",
			wantMethod: "tag-heuristic",
		},
		{
			name: "step 3 wins: no VCS, no usable tag, --go-vcs-url provided",
			info: &GoBinaryInfo{
				Path:       "/opt/cni/bin/calico",
				MainModule: "github.com/projectcalico/calico",
			},
			imageRef:   "docker.io/calico/cni:latest",
			goVCSURL:   "https://github.com/projectcalico/calico@v3.31.4",
			wantMethod: "vcs-override",
		},
		{
			name: "all steps fail",
			info: &GoBinaryInfo{
				Path: "/bin/unknown",
			},
			imageRef: "unknown:latest",
			goVCSURL: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveGoSource(tt.info, tt.imageRef, tt.goVCSURL)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "all resolution methods failed")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, got.Method)
			assert.NotEmpty(t, got.Repo)
			assert.NotEmpty(t, got.Ref)
		})
	}
}

func TestExtractImageTag(t *testing.T) {
	tests := []struct {
		imageRef string
		want     string
	}{
		{"quay.io/prometheus/prometheus:v3.9.1", "v3.9.1"},
		{"influxdb:2.8.0", "2.8.0"},
		{"docker.io/calico/cni:v3.31.4", "v3.31.4"},
		{"hashicorp/vault:1.21.3", "1.21.3"},
		{"image@sha256:abc123", ""},
		{"registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.18.0", "v2.18.0"},
		{"image", ""},
		{"localhost:5000/app:v1", "v1"},
		{"ghcr.io/user/repo:latest", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.imageRef, func(t *testing.T) {
			got := extractImageTag(tt.imageRef)
			assert.Equal(t, tt.want, got)
		})
	}
}
