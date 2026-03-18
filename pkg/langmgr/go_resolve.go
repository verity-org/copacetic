package langmgr

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// GoSourceResolution holds the result of resolving where to find source code for a Go binary.
type GoSourceResolution struct {
	Repo   string // Git repository URL
	Ref    string // Git ref (commit, tag, or branch)
	Method string // How it was resolved: "binary-vcs", "tag-heuristic", "vcs-override"
}

// resolveGoSource attempts to find the source code for a Go binary using a 3-step resolution chain:
//  1. Auto-detect: Use VCS revision from go version -m output
//  2. Tag heuristic: Derive repo from module path + try image tag as git ref
//  3. VCS override: Use the user-provided --go-vcs-url value (format: "repo@ref" or just "repo")
//
// Returns the first successful resolution. Returns an error if all methods fail.
func resolveGoSource(info *GoBinaryInfo, imageRef string, goVCSURL string) (*GoSourceResolution, error) {
	if info == nil {
		return nil, fmt.Errorf("nil binary info")
	}

	var attempts []string

	// Step 1: Auto-detect from binary VCS info
	resolution, err := resolveFromBinary(info)
	if err == nil {
		return resolution, nil
	}
	attempts = append(attempts, fmt.Sprintf("binary-vcs: %v", err))

	// Step 2: Tag heuristic — derive repo from module path, use image tag as ref
	resolution, err = resolveFromTagHeuristic(info, imageRef)
	if err == nil {
		return resolution, nil
	}
	attempts = append(attempts, fmt.Sprintf("tag-heuristic: %v", err))

	// Step 3: VCS override — parse --go-vcs-url flag value
	resolution, err = resolveFromVCSOverride(goVCSURL, imageRef)
	if err == nil {
		return resolution, nil
	}
	attempts = append(attempts, fmt.Sprintf("vcs-override: %v", err))

	return nil, fmt.Errorf("all resolution methods failed for binary %s: %s", info.Path, strings.Join(attempts, "; "))
}

// resolveFromBinary attempts to resolve source from the binary's embedded VCS info.
// This requires both a VCS revision and a derivable repo URL from the module path.
func resolveFromBinary(info *GoBinaryInfo) (*GoSourceResolution, error) {
	if info.VCSRevision == "" {
		return nil, fmt.Errorf("no VCS revision embedded in binary")
	}

	modulePath := info.MainModule
	if modulePath == "" || modulePath == "command-line-arguments" {
		return nil, fmt.Errorf("no module path available (built without module)")
	}

	repo := deriveRepoFromModulePath(modulePath)
	if repo == "" {
		return nil, fmt.Errorf("could not derive repo URL from module path %q", modulePath)
	}

	log.Debugf("Resolved source from binary VCS: %s @ %s", repo, info.VCSRevision)
	return &GoSourceResolution{
		Repo:   repo,
		Ref:    info.VCSRevision,
		Method: "binary-vcs",
	}, nil
}

// resolveFromTagHeuristic attempts to resolve source by deriving the repo from the module path
// and using the image tag as a potential git tag/ref.
//
// For example, image "quay.io/prometheus/prometheus:v3.9.1" with module "github.com/prometheus/prometheus"
// would try repo "https://github.com/prometheus/prometheus" at ref "v3.9.1".
func resolveFromTagHeuristic(info *GoBinaryInfo, imageRef string) (*GoSourceResolution, error) {
	modulePath := info.MainModule
	if modulePath == "" || modulePath == "command-line-arguments" {
		return nil, fmt.Errorf("no module path available for tag heuristic")
	}

	tag := extractImageTag(imageRef)
	if tag == "" || tag == "latest" {
		return nil, fmt.Errorf("no usable tag in image reference %q", imageRef)
	}

	repo := deriveRepoFromModulePath(modulePath)
	if repo == "" {
		return nil, fmt.Errorf("could not derive repo URL from module path %q", modulePath)
	}

	log.Debugf("Resolved source via tag heuristic: %s @ %s (from image tag)", repo, tag)
	return &GoSourceResolution{
		Repo:   repo,
		Ref:    tag,
		Method: "tag-heuristic",
	}, nil
}

// resolveFromVCSOverride parses a --go-vcs-url flag value and returns a resolution.
//
// Accepted formats:
//
//	"https://github.com/org/repo@v1.0.0"  → repo + explicit ref
//	"https://github.com/org/repo"          → repo + ref from image tag
func resolveFromVCSOverride(goVCSURL, imageRef string) (*GoSourceResolution, error) {
	goVCSURL = strings.TrimSpace(goVCSURL)
	if goVCSURL == "" {
		return nil, fmt.Errorf("no --go-vcs-url provided")
	}

	repo, ref := parseVCSURL(goVCSURL)

	// If no explicit ref, try to extract from image tag
	if ref == "" {
		ref = extractImageTag(imageRef)
		if ref == "" || ref == "latest" {
			return nil, fmt.Errorf("--go-vcs-url %q has no @ref and image %q has no usable tag", goVCSURL, imageRef)
		}
	}

	log.Debugf("Resolved source from --go-vcs-url: %s @ %s", repo, ref)
	return &GoSourceResolution{
		Repo:   repo,
		Ref:    ref,
		Method: "vcs-override",
	}, nil
}

// parseVCSURL splits a VCS URL into repo and optional ref.
// "https://github.com/org/repo@v1.0" → ("https://github.com/org/repo", "v1.0")
// "https://github.com/org/repo"       → ("https://github.com/org/repo", "")
func parseVCSURL(vcsURL string) (repo, ref string) {
	// Find @ that's after the scheme (not in https://)
	idx := strings.LastIndex(vcsURL, "@")
	if idx > 0 {
		// Make sure @ is after any :// scheme
		schemeEnd := strings.Index(vcsURL, "://")
		if schemeEnd < 0 || idx > schemeEnd+3 {
			return vcsURL[:idx], vcsURL[idx+1:]
		}
	}
	return vcsURL, ""
}

// extractImageTag extracts the tag from a container image reference.
// e.g., "quay.io/prometheus/prometheus:v3.9.1" → "v3.9.1"
// e.g., "influxdb:2.8.0" → "2.8.0"
// e.g., "image@sha256:abc" → "" (digest, no tag)
func extractImageTag(imageRef string) string {
	// Remove digest if present
	if idx := strings.Index(imageRef, "@"); idx >= 0 {
		imageRef = imageRef[:idx]
	}

	// Find the tag after the last colon (but not in the host:port part)
	lastColon := strings.LastIndex(imageRef, ":")
	if lastColon < 0 {
		return ""
	}

	// Make sure the colon is after the last slash (i.e., it's a tag separator, not host:port)
	lastSlash := strings.LastIndex(imageRef, "/")
	if lastColon < lastSlash {
		return ""
	}

	return imageRef[lastColon+1:]
}
