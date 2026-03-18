package langmgr

import (
	"fmt"
	"strings"
)

// ModuleInfo represents a Go module dependency extracted from go version -m output.
type ModuleInfo struct {
	Path    string // Module path (e.g., "github.com/user/repo")
	Version string // Module version (e.g., "v1.2.3")
	Hash    string // Module hash (e.g., "h1:abc...")
}

// GoBinaryInfo holds parsed information from `go version -m` output for a single binary.
type GoBinaryInfo struct {
	Path          string            // Binary path in the container image
	GoVersion     string            // Go compiler version (e.g., "go1.22.5")
	MainModule    string            // Main module path (from mod line)
	MainVersion   string            // Main module version (from mod line)
	MainPath      string            // Main package build path (from path line)
	VCSRevision   string            // vcs.revision build setting (empty if stripped)
	VCSTime       string            // vcs.time build setting
	VCSModified   bool              // vcs.modified build setting
	CGOEnabled    bool              // CGO_ENABLED build setting
	BuildSettings map[string]string // All build settings from build lines
	Deps          []ModuleInfo      // All dependency modules from dep lines
}

// parseGoBuildInfo parses the combined output of `go version -m` which can contain
// information for multiple binaries. Each binary section starts with a line like:
//
//	/path/to/binary: go1.22.5
//
// Returns a slice of GoBinaryInfo, one per binary found in the output.
func parseGoBuildInfo(output string) ([]*GoBinaryInfo, error) {
	if strings.TrimSpace(output) == "" {
		return nil, fmt.Errorf("empty go version -m output")
	}

	var result []*GoBinaryInfo
	var current *GoBinaryInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Check for binary header line: "/path/to/binary: go1.22.5"
		// These lines don't start with a tab and contain ": go"
		if !strings.HasPrefix(line, "\t") && strings.Contains(line, ": go") {
			colonIdx := strings.LastIndex(line, ": go")
			if colonIdx >= 0 {
				binaryPath := strings.TrimSpace(line[:colonIdx])
				goVersion := strings.TrimSpace(line[colonIdx+2:])

				current = &GoBinaryInfo{
					Path:          binaryPath,
					GoVersion:     goVersion,
					BuildSettings: make(map[string]string),
				}
				result = append(result, current)
				continue
			}
		}

		// All subsequent lines should be tab-prefixed and belong to current binary
		if current == nil {
			continue
		}

		trimmed := strings.TrimPrefix(line, "\t")
		if trimmed == line {
			// Not tab-prefixed, skip
			continue
		}

		fields := strings.SplitN(trimmed, "\t", 4)
		if len(fields) < 2 {
			continue
		}

		keyword := fields[0]
		switch keyword {
		case "path":
			current.MainPath = fields[1]

		case "mod":
			current.MainModule = fields[1]
			if len(fields) >= 3 {
				current.MainVersion = fields[2]
			}

		case "dep":
			dep := ModuleInfo{Path: fields[1]}
			if len(fields) >= 3 {
				dep.Version = fields[2]
			}
			if len(fields) >= 4 {
				dep.Hash = fields[3]
			}
			current.Deps = append(current.Deps, dep)

		case "build":
			// Build settings are in "key=value" format
			if len(fields) >= 2 {
				kv := fields[1]
				eqIdx := strings.Index(kv, "=")
				if eqIdx >= 0 {
					key := kv[:eqIdx]
					value := kv[eqIdx+1:]
					current.BuildSettings[key] = value

					// Extract well-known settings into struct fields
					switch key {
					case "vcs.revision":
						current.VCSRevision = value
					case "vcs.time":
						current.VCSTime = value
					case "vcs.modified":
						current.VCSModified = value == "true"
					case "CGO_ENABLED":
						current.CGOEnabled = value == "1"
					}
				} else {
					// Some build settings are flags without values (e.g., "-buildmode=exe")
					current.BuildSettings[kv] = ""
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no Go binaries found in go version -m output")
	}

	return result, nil
}

// knownModuleToRepo maps well-known Go module path prefixes to their Git repository URLs.
var knownModuleToRepo = map[string]string{
	"golang.org/x/":       "https://github.com/golang/",
	"k8s.io/":             "https://github.com/kubernetes/",
	"sigs.k8s.io/":        "https://github.com/kubernetes-sigs/",
	"istio.io/":           "https://github.com/istio/",
	"go.etcd.io/":         "https://github.com/etcd-io/",
	"go.uber.org/":        "https://github.com/uber-go/",
	"cloud.google.com/go": "https://github.com/googleapis/google-cloud-go",
}

// deriveRepoFromModulePath converts a Go module path to a probable Git repository URL.
//
// Examples:
//
//	github.com/prometheus/prometheus     → https://github.com/prometheus/prometheus
//	github.com/influxdata/influxdb/v2   → https://github.com/influxdata/influxdb
//	golang.org/x/net                    → https://github.com/golang/net
//	k8s.io/api                          → https://github.com/kubernetes/api
func deriveRepoFromModulePath(modulePath string) string {
	if modulePath == "" {
		return ""
	}

	// Strip Go major version suffix (/v2, /v3, etc.)
	modulePath = stripGoMajorVersion(modulePath)

	// Check known mappings (prefix-based)
	for prefix, repoPrefix := range knownModuleToRepo {
		if strings.HasPrefix(modulePath, prefix) {
			suffix := strings.TrimPrefix(modulePath, prefix)
			// For exact matches (like cloud.google.com/go), no suffix
			if suffix == "" {
				return repoPrefix
			}
			// Take only the first path component after the prefix
			parts := strings.SplitN(suffix, "/", 2)
			return repoPrefix + parts[0]
		}
	}

	// For github.com, gitlab.com, bitbucket.org — extract org/repo
	parts := strings.Split(modulePath, "/")
	if len(parts) >= 3 {
		host := parts[0]
		if host == "github.com" || host == "gitlab.com" || host == "bitbucket.org" {
			return "https://" + strings.Join(parts[:3], "/")
		}
	}

	// Generic fallback: use https://module-path but take only first 3 components
	if len(parts) >= 3 {
		return "https://" + strings.Join(parts[:3], "/")
	}
	return "https://" + modulePath
}

// stripGoMajorVersion removes the Go major version suffix from a module path.
// e.g., "github.com/user/repo/v2" → "github.com/user/repo"
func stripGoMajorVersion(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	last := parts[len(parts)-1]
	if len(last) >= 2 && last[0] == 'v' {
		allDigits := true
		for _, c := range last[1:] {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return modulePath
}
