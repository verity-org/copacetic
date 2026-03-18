package langmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoBuildInfo(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
		validate  func(t *testing.T, infos []*GoBinaryInfo)
	}{
		{
			name: "full output with VCS (Prometheus-style)",
			input: `/bin/prometheus: go1.25.5
	path	github.com/prometheus/prometheus/cmd/prometheus
	mod	github.com/prometheus/prometheus	v0.0.0-20260107160527-9ec59baffb54+dirty	
	dep	github.com/cespare/xxhash/v2	v2.3.0	h1:UL815xU9SqsFlibzuggzjXhog7bL6oX9BbNZnL2UFvs=
	dep	golang.org/x/sys	v0.30.0	h1:QjkSwP/36a20jFYWkSue1YwXzLmsV5Gfq7Eiy72C1uc=
	build	-buildmode=exe
	build	-compiler=gc
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux
	build	vcs=git
	build	vcs.revision=9ec59baffb547e24f1468a53eb82901e58feabd8
	build	vcs.time=2026-01-07T16:05:27Z
	build	vcs.modified=true`,
			wantCount: 1,
			validate: func(t *testing.T, infos []*GoBinaryInfo) {
				info := infos[0]
				assert.Equal(t, "/bin/prometheus", info.Path)
				assert.Equal(t, "go1.25.5", info.GoVersion)
				assert.Equal(t, "github.com/prometheus/prometheus/cmd/prometheus", info.MainPath)
				assert.Equal(t, "github.com/prometheus/prometheus", info.MainModule)
				assert.Equal(t, "v0.0.0-20260107160527-9ec59baffb54+dirty", info.MainVersion)
				assert.Equal(t, "9ec59baffb547e24f1468a53eb82901e58feabd8", info.VCSRevision)
				assert.Equal(t, "2026-01-07T16:05:27Z", info.VCSTime)
				assert.True(t, info.VCSModified)
				assert.False(t, info.CGOEnabled)
				assert.Equal(t, "0", info.BuildSettings["CGO_ENABLED"])
				assert.Equal(t, "amd64", info.BuildSettings["GOARCH"])
				assert.Equal(t, "linux", info.BuildSettings["GOOS"])
				assert.Len(t, info.Deps, 2)
				assert.Equal(t, "github.com/cespare/xxhash/v2", info.Deps[0].Path)
				assert.Equal(t, "v2.3.0", info.Deps[0].Version)
			},
		},
		{
			name: "no VCS info (Calico-style)",
			input: `/opt/cni/bin/calico: go1.24.13
	path	github.com/projectcalico/calico/cni-plugin/cmd/calico
	mod	github.com/projectcalico/calico	(devel)	
	dep	github.com/Microsoft/go-winio	v0.6.2	h1:F2VQtest=
	build	-buildmode=exe
	build	-compiler=gc
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux`,
			wantCount: 1,
			validate: func(t *testing.T, infos []*GoBinaryInfo) {
				info := infos[0]
				assert.Equal(t, "/opt/cni/bin/calico", info.Path)
				assert.Equal(t, "go1.24.13", info.GoVersion)
				assert.Equal(t, "github.com/projectcalico/calico", info.MainModule)
				assert.Equal(t, "(devel)", info.MainVersion)
				assert.Empty(t, info.VCSRevision, "Calico-style binaries should have no VCS revision")
				assert.Empty(t, info.VCSTime)
				assert.False(t, info.CGOEnabled)
				assert.Len(t, info.Deps, 1)
			},
		},
		{
			name: "CGO enabled (InfluxDB-style)",
			input: `/usr/bin/influxd: go1.22.4
	path	github.com/influxdata/influxdb/v2/cmd/influxd
	mod	github.com/influxdata/influxdb/v2	v2.8.0	h1:abc123=
	dep	github.com/apache/arrow/go/v7	v7.0.1	h1:def456=
	build	CGO_ENABLED=1
	build	GOARCH=amd64
	build	GOOS=linux
	build	vcs=git
	build	vcs.revision=abcdef1234567890`,
			wantCount: 1,
			validate: func(t *testing.T, infos []*GoBinaryInfo) {
				info := infos[0]
				assert.Equal(t, "/usr/bin/influxd", info.Path)
				assert.True(t, info.CGOEnabled)
				assert.Equal(t, "1", info.BuildSettings["CGO_ENABLED"])
				assert.Equal(t, "abcdef1234567890", info.VCSRevision)
				assert.Equal(t, "github.com/influxdata/influxdb/v2", info.MainModule)
				assert.Equal(t, "v2.8.0", info.MainVersion)
			},
		},
		{
			name: "multiple binaries in one output",
			input: `/bin/prometheus: go1.25.5
	path	github.com/prometheus/prometheus/cmd/prometheus
	mod	github.com/prometheus/prometheus	v0.0.0-20260107	
	dep	golang.org/x/net	v0.30.0	h1:abc=
	build	CGO_ENABLED=0
	build	vcs.revision=aaa111

/bin/promtool: go1.25.5
	path	github.com/prometheus/prometheus/cmd/promtool
	mod	github.com/prometheus/prometheus	v0.0.0-20260107	
	dep	golang.org/x/net	v0.30.0	h1:abc=
	build	CGO_ENABLED=0
	build	vcs.revision=aaa111`,
			wantCount: 2,
			validate: func(t *testing.T, infos []*GoBinaryInfo) {
				assert.Equal(t, "/bin/prometheus", infos[0].Path)
				assert.Equal(t, "/bin/promtool", infos[1].Path)
				assert.Equal(t, "aaa111", infos[0].VCSRevision)
				assert.Equal(t, "aaa111", infos[1].VCSRevision)
			},
		},
		{
			name: "stripped/minimal output (configmap-reload style)",
			input: `/configmap-reload: go1.24.2
	path	command-line-arguments
	dep	github.com/fsnotify/fsnotify	v1.9.0	h1:2Ml+test=
	build	CGO_ENABLED=0`,
			wantCount: 1,
			validate: func(t *testing.T, infos []*GoBinaryInfo) {
				info := infos[0]
				assert.Equal(t, "/configmap-reload", info.Path)
				assert.Equal(t, "go1.24.2", info.GoVersion)
				assert.Equal(t, "command-line-arguments", info.MainPath)
				assert.Empty(t, info.MainModule, "no mod line means empty main module")
				assert.Empty(t, info.VCSRevision)
				assert.False(t, info.CGOEnabled)
				assert.Len(t, info.Deps, 1)
			},
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   \n  \n  ",
			wantErr: true,
		},
		{
			name:    "non-Go binary output",
			input:   "/usr/bin/bash: not a Go binary",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos, err := parseGoBuildInfo(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, infos, tt.wantCount)
			if tt.validate != nil {
				tt.validate(t, infos)
			}
		})
	}
}

func TestDeriveRepoFromModulePath(t *testing.T) {
	tests := []struct {
		modulePath string
		want       string
	}{
		{
			modulePath: "github.com/prometheus/prometheus",
			want:       "https://github.com/prometheus/prometheus",
		},
		{
			modulePath: "github.com/influxdata/influxdb/v2",
			want:       "https://github.com/influxdata/influxdb",
		},
		{
			modulePath: "github.com/projectcalico/calico",
			want:       "https://github.com/projectcalico/calico",
		},
		{
			modulePath: "golang.org/x/net",
			want:       "https://github.com/golang/net",
		},
		{
			modulePath: "golang.org/x/sys",
			want:       "https://github.com/golang/sys",
		},
		{
			modulePath: "golang.org/x/crypto",
			want:       "https://github.com/golang/crypto",
		},
		{
			modulePath: "k8s.io/api",
			want:       "https://github.com/kubernetes/api",
		},
		{
			modulePath: "k8s.io/client-go",
			want:       "https://github.com/kubernetes/client-go",
		},
		{
			modulePath: "sigs.k8s.io/controller-runtime",
			want:       "https://github.com/kubernetes-sigs/controller-runtime",
		},
		{
			modulePath: "istio.io/istio",
			want:       "https://github.com/istio/istio",
		},
		{
			modulePath: "go.etcd.io/etcd/v3",
			want:       "https://github.com/etcd-io/etcd",
		},
		{
			modulePath: "go.uber.org/zap",
			want:       "https://github.com/uber-go/zap",
		},
		{
			modulePath: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.modulePath, func(t *testing.T) {
			got := deriveRepoFromModulePath(tt.modulePath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStripGoMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com/user/repo/v2", "github.com/user/repo"},
		{"github.com/user/repo/v3", "github.com/user/repo"},
		{"github.com/user/repo/v10", "github.com/user/repo"},
		{"github.com/user/repo", "github.com/user/repo"},
		{"github.com/user/repo/pkg", "github.com/user/repo/pkg"},
		{"github.com/user/repo/v2beta", "github.com/user/repo/v2beta"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripGoMajorVersion(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
