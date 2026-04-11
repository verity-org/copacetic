package provenance

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/buildkit/client/llb"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// errSourceNotCloned is returned when source code cannot be cloned and no
// build can be attempted. The caller should skip the binary gracefully.
var errSourceNotCloned = fmt.Errorf("source code not available for rebuild")

// discoverAndBuildScript is a shell script that discovers the main package
// directory in a cloned Go repository and builds the binary from it.
// Arguments: $1=binary-name $2=output-path $3=explicit-main-pkg
// Reads the go build command prefix (without main pkg arg) from /tmp/copa_build_prefix.
const discoverAndBuildScript = `#!/bin/sh
BINARY_NAME="$1"
OUTPUT="$2"
EXPLICIT_PKG="$3"
BUILD_PREFIX="$(cat /tmp/copa_build_prefix)"

run_build() {
    echo "Copa: building from $1"
    eval "$BUILD_PREFIX $1"
}

# Strategy 1: Explicit main package path (from go version -m metadata)
if [ -n "$EXPLICIT_PKG" ] && [ "$EXPLICIT_PKG" != "." ]; then
    stripped=$(echo "$EXPLICIT_PKG" | sed 's|^\./||')
    if [ -d "$stripped" ]; then
        run_build "$EXPLICIT_PKG"
        exit $?
    fi
    echo "Copa: explicit path $EXPLICIT_PKG not found, trying discovery..."
fi

# Strategy 2: Root directory has Go source files
if ls *.go 1>/dev/null 2>&1; then
    run_build "."
    exit $?
fi

# Strategy 3: cmd/<binary-name>/
if [ -d "cmd/$BINARY_NAME" ]; then
    run_build "./cmd/$BINARY_NAME"
    exit $?
fi

# Strategy 4: First cmd/ subdirectory with Go files
for d in cmd/*/; do
    [ -d "$d" ] || continue
    if ls "${d}"*.go 1>/dev/null 2>&1; then
        run_build "./${d%/}"
        exit $?
    fi
done

# Strategy 5: Find main.go in directory matching binary name
FOUND=$(find . -name main.go -not -path "*/vendor/*" -not -path "*/_*" -not -path "*/testdata/*" 2>/dev/null | while IFS= read -r f; do
    dir=$(dirname "$f")
    case "$dir" in *"$BINARY_NAME"*) echo "$dir"; break;; esac
done | head -1)
if [ -n "$FOUND" ]; then
    run_build "$FOUND"
    exit $?
fi

# Strategy 6: First main.go found anywhere (excluding vendor/test)
FIRST_DIR=$(find . -name main.go -not -path "*/vendor/*" -not -path "*/_*" -not -path "*/testdata/*" -exec dirname {} \; 2>/dev/null | head -1)
if [ -n "$FIRST_DIR" ]; then
    run_build "$FIRST_DIR"
    exit $?
fi

# Nothing found - fail the build so the original binary is preserved
echo "ERROR: no buildable Go source found for $BINARY_NAME in cloned repository"
echo "The source was cloned but no main package could be discovered."
echo "Tried: explicit path, root dir, cmd/<name>/, cmd/*/, main.go matching, first main.go"
exit 1
`

// normalizeVersion ensures a version string has the 'v' prefix required by Go modules.
func normalizeVersion(version string) string {
	if version == "" {
		return version
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// validateBinaryPath validates that a binary path is safe and absolute.
// It prevents path traversal attacks and ensures the path is suitable for use.
func validateBinaryPath(path string) error {
	if path == "" {
		return fmt.Errorf("binary path is empty")
	}

	// Must be absolute path
	if !filepath.IsAbs(path) {
		return fmt.Errorf("binary path must be absolute: %s", path)
	}

	// Check for path traversal attempts
	cleanPath := filepath.Clean(path)
	if cleanPath != path && !strings.HasPrefix(cleanPath, path) {
		// Allow minor normalization (trailing slashes, etc.)
		// but reject clear traversal patterns
		if strings.Contains(path, "..") {
			return fmt.Errorf("binary path contains traversal pattern: %s", path)
		}
	}

	// Reject paths that could escape expected locations
	if strings.Contains(path, "..") {
		return fmt.Errorf("binary path contains parent directory reference: %s", path)
	}

	// Reject paths with null bytes (injection attempt)
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("binary path contains null byte: %s", path)
	}

	// Reject paths with shell metacharacters
	if strings.ContainsAny(path, "|;&$`\\\"'<>(){}[]!#~") {
		return fmt.Errorf("binary path contains unsafe characters: %s", path)
	}

	return nil
}

// shellUnsafeChars are characters that must not appear in values interpolated into shell commands.
const shellUnsafeChars = ";&|`$(){}[]<>\\*?!~#\t\n\r"

// shellUnsafeCharsStrict includes quotes, for contexts where even quoting is suspicious.
const shellUnsafeCharsStrict = shellUnsafeChars + "\"'"

// validateShellSafe checks that a string is safe to interpolate into a shell command.
// It allows quotes (needed for Go -ldflags values) but blocks injection characters.
func validateShellSafe(value, label string) error {
	if strings.ContainsAny(value, shellUnsafeChars) {
		return fmt.Errorf("%s contains unsafe characters: %s", label, value)
	}
	return nil
}

// validateShellSafeStrict checks that a string has no unsafe characters including quotes.
// Use for simple values like GOOS, GOARCH, package paths where quotes are never expected.
func validateShellSafeStrict(value, label string) error {
	if strings.ContainsAny(value, shellUnsafeCharsStrict) {
		return fmt.Errorf("%s contains unsafe characters: %s", label, value)
	}
	return nil
}

func validateGoModuleName(module string) error {
	if strings.ContainsAny(module, ";&|`$(){}[]<>\"'\\*?!~# \t\n\r") {
		return fmt.Errorf("module name contains unsafe characters: %s", module)
	}
	if strings.HasPrefix(module, "-") {
		return fmt.Errorf("module name cannot start with '-': %s", module)
	}
	return nil
}

// Rebuilder orchestrates the Go binary rebuild process using heuristic detection.
type Rebuilder struct{}

// NewRebuilder creates a new binary rebuilder.
func NewRebuilder() *Rebuilder {
	return &Rebuilder{}
}

// RebuildBinary rebuilds a Go binary with updated dependencies and merges it back into the target image.
func (r *Rebuilder) RebuildBinary(
	rebuildCtx *RebuildContext,
	updates map[string]string,
	platform *specs.Platform,
	targetState *llb.State,
	binaryPath string,
) (llb.State, *RebuildResult, error) {
	result := &RebuildResult{
		Strategy:        rebuildCtx.Strategy.String(),
		RebuiltBinaries: make(map[string]bool),
	}

	// Validate inputs with detailed error messages
	if rebuildCtx.Strategy == RebuildStrategyNone {
		result.Error = fmt.Errorf("no rebuild strategy available for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	buildInfo := rebuildCtx.BuildInfo
	if buildInfo == nil {
		result.Error = fmt.Errorf("no build information available for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	if targetState == nil {
		result.Error = fmt.Errorf("no target state provided for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	// Validate the binary path for security
	if err := validateBinaryPath(binaryPath); err != nil {
		result.Error = fmt.Errorf("invalid binary path: %w", err)
		return llb.State{}, result, result.Error
	}

	// Extract binary name from path (e.g., /coredns -> coredns)
	binaryName := filepath.Base(binaryPath)
	outputPath := "/output/" + binaryName

	log.Infof("Rebuilding Go binary %s using %s strategy", binaryPath, result.Strategy)
	log.Debugf("Binary details: module=%s, Go version=%s, %d dependencies",
		buildInfo.ModulePath, buildInfo.GoVersion, len(buildInfo.Dependencies))

	// Determine base image for build
	baseImage := r.determineBaseImage(buildInfo)
	if baseImage == "" {
		result.Error = fmt.Errorf("cannot determine base image for rebuild of %s: no Go version found (module: %s)",
			binaryPath, buildInfo.ModulePath)
		result.Warnings = append(result.Warnings, "No Go version found in binary info")
		return llb.State{}, result, result.Error
	}
	log.Infof("Using base image: %s", baseImage)

	// Build the new binary with updated dependencies (outputs to /output/<name>)
	buildState, err := r.buildBinaryWithUpdates(baseImage, rebuildCtx, buildInfo, updates, platform, outputPath)
	if err != nil {
		if err == errSourceNotCloned {
			// Source not available — can't rebuild binary, but this is not a fatal error.
			// Return the original target state unchanged so the binary is preserved.
			result.Success = false
			result.Error = fmt.Errorf("source code not available for %s (module: %s) — binary preserved, Go vulnerabilities remain",
				binaryPath, buildInfo.ModulePath)
			result.Warnings = append(result.Warnings, result.Error.Error())
			log.Warnf("%v", result.Error)
			return *targetState, result, nil
		}
		result.Error = fmt.Errorf("failed to rebuild binary %s (module: %s, Go: %s): %w",
			binaryPath, buildInfo.ModulePath, buildInfo.GoVersion, err)
		return llb.State{}, result, result.Error
	}

	// Copy the rebuilt binary from build container to target image
	// This is a pure LLB operation - works on distroless images (no shell needed)
	log.Infof("Copying rebuilt binary from %s to target at %s", outputPath, binaryPath)
	copyInfo := &llb.CopyInfo{
		CreateDestPath:      true,
		AllowWildcard:       false,
		AllowEmptyWildcard:  false,
		CopyDirContentsOnly: false,
	}

	// Preserve original binary's file permissions and ownership
	if len(rebuildCtx.BinaryInfo) > 0 {
		bi := rebuildCtx.BinaryInfo[0]
		if bi.FileMode != "" {
			if mode, err := strconv.ParseUint(bi.FileMode, 8, 32); err == nil {
				// Strip setuid/setgid/sticky bits from raw Unix mode BEFORE casting.
				// os.FileMode uses different bit positions than Unix, so we must
				// clear bits 0o7000 on the raw value, not on the os.FileMode.
				if mode&0o7000 != 0 {
					log.Warnf("Stripping setuid/setgid/sticky bits from rebuilt binary (original mode: 0%o)", mode)
					mode &^= 0o7000
				}
				fmode := os.FileMode(mode)
				copyInfo.Mode = &llb.ChmodOpt{Mode: fmode}
				log.Debugf("Preserving file mode: 0%o", fmode)
			}
		}
		if bi.FileOwner != "" {
			parts := strings.SplitN(bi.FileOwner, ":", 2)
			if len(parts) == 2 {
				uid, uidErr := strconv.Atoi(parts[0])
				gid, gidErr := strconv.Atoi(parts[1])
				if uidErr == nil && gidErr == nil {
					copyInfo.ChownOpt = &llb.ChownOpt{
						User:  &llb.UserOpt{UID: uid},
						Group: &llb.UserOpt{UID: gid},
					}
					log.Debugf("Preserving file ownership: %d:%d", uid, gid)
				}
			}
		}
	}

	modifiedTarget := targetState.File(
		llb.Copy(buildState, outputPath, binaryPath, copyInfo),
	)

	// Capture only the diff (like dotnet patching)
	patchDiff := llb.Diff(*targetState, modifiedTarget)

	// Squash the diff into a single layer
	squashedPatch := llb.Scratch().File(
		llb.Copy(patchDiff, "/", "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
	)

	// Merge the patch back into the original image
	finalState := llb.Merge([]llb.State{*targetState, squashedPatch})

	result.Success = true
	result.BinariesRebuilt = 1
	result.RebuiltBinaries[binaryPath] = true

	log.Infof("Successfully merged rebuilt binary into target image")
	return finalState, result, nil
}

// golangToolingTag is the Docker tag used for Go tooling images (detection,
// rebuilding, etc.). We use "1" (latest stable Go 1.x) rather than a pinned
// minor version because updated dependencies often require a newer Go, and Go
// maintains strong backwards compatibility so using a newer toolchain is safe.
const golangToolingTag = "1"

// determineBaseImage selects the best base image for rebuilding.
// Uses the latest stable Go toolchain to ensure compatibility with updated dependencies.
func (r *Rebuilder) determineBaseImage(buildInfo *BuildInfo) string {
	if buildInfo.BaseImage != "" {
		return buildInfo.BaseImage
	}

	if buildInfo.GoVersion != "" {
		image := "golang:" + golangToolingTag
		log.Debugf("Binary was built with Go %s, using latest stable toolchain (%s) for compatibility with updated dependencies",
			buildInfo.GoVersion, image)
		return image
	}

	return ""
}

// deriveRepoFromModulePath attempts to derive a Git repository URL from a Go module path.
func deriveRepoFromModulePath(modulePath string) (repoURL string, subpath string) {
	if modulePath == "" {
		return "", ""
	}

	// Handle github.com modules directly
	if strings.HasPrefix(modulePath, "github.com/") {
		parts := strings.Split(modulePath, "/")
		if len(parts) >= 3 {
			repoURL = fmt.Sprintf("https://github.com/%s/%s", parts[1], parts[2])
			if len(parts) > 3 {
				subpath = strings.Join(parts[3:], "/")
			}
			return repoURL, subpath
		}
	}

	// Handle k8s.io vanity imports -> github.com/kubernetes/*
	if strings.HasPrefix(modulePath, "k8s.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repo := parts[1]
			repoURL = fmt.Sprintf("https://github.com/kubernetes/%s", repo)
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	// Handle golang.org/x/* -> github.com/golang/*
	if strings.HasPrefix(modulePath, "golang.org/x/") {
		parts := strings.SplitN(modulePath, "/", 4)
		if len(parts) >= 3 {
			repoURL = fmt.Sprintf("https://github.com/golang/%s", parts[2])
			if len(parts) >= 4 {
				subpath = parts[3]
			}
			return repoURL, subpath
		}
	}

	// Handle sigs.k8s.io/* -> github.com/kubernetes-sigs/*
	if strings.HasPrefix(modulePath, "sigs.k8s.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repoURL = fmt.Sprintf("https://github.com/kubernetes-sigs/%s", parts[1])
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	if strings.HasPrefix(modulePath, "cloud.google.com/go/") || modulePath == "cloud.google.com/go" {
		parts := strings.Split(modulePath, "/")
		repoURL = "https://github.com/googleapis/google-cloud-go"
		if len(parts) > 2 {
			subpath = strings.Join(parts[2:], "/")
		}
		return repoURL, subpath
	}

	if strings.HasPrefix(modulePath, "go.uber.org/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repoURL = fmt.Sprintf("https://github.com/uber-go/%s", parts[1])
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	if strings.HasPrefix(modulePath, "go.etcd.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repoURL = fmt.Sprintf("https://github.com/etcd-io/%s", parts[1])
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	if strings.HasPrefix(modulePath, "go.opentelemetry.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repoURL = fmt.Sprintf("https://github.com/open-telemetry/%s", parts[1])
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	if modulePath == "google.golang.org/grpc" || strings.HasPrefix(modulePath, "google.golang.org/grpc/") {
		repoURL = "https://github.com/grpc/grpc-go"
		if modulePath != "google.golang.org/grpc" {
			subpath = strings.TrimPrefix(modulePath, "google.golang.org/grpc/")
		}
		return repoURL, subpath
	}

	if modulePath == "google.golang.org/protobuf" || strings.HasPrefix(modulePath, "google.golang.org/protobuf/") {
		repoURL = "https://github.com/protocolbuffers/protobuf-go"
		if modulePath != "google.golang.org/protobuf" {
			subpath = strings.TrimPrefix(modulePath, "google.golang.org/protobuf/")
		}
		return repoURL, subpath
	}

	return "", ""
}

// stripGoMajorVersionSuffix removes Go major version suffixes (v2, v3, etc.)
// from repository subpaths. In Go modules, paths like "github.com/foo/bar/v2"
// include /v2 to indicate major version 2, but the source code is typically at
// the repository root, not in a v2/ subdirectory.
func stripGoMajorVersionSuffix(subpath string) string {
	if subpath == "" {
		return ""
	}
	parts := strings.Split(subpath, "/")
	last := parts[len(parts)-1]
	if len(last) >= 2 && last[0] == 'v' {
		if n, err := strconv.Atoi(last[1:]); err == nil && n >= 2 {
			parts = parts[:len(parts)-1]
			return strings.Join(parts, "/")
		}
	}
	return subpath
}

// validateRepoURL checks that a repository URL is from a trusted host.
// Only repositories from known hosts are allowed to prevent supply chain attacks
// via crafted binary metadata pointing to malicious repositories.
func validateRepoURL(repoURL string) error {
	trustedPrefixes := []string{
		"https://github.com/",
	}
	for _, prefix := range trustedPrefixes {
		if strings.HasPrefix(repoURL, prefix) {
			return nil
		}
	}
	return fmt.Errorf("repository URL %q is not from a trusted host (only github.com is supported)", repoURL)
}

// validateCommitHash checks that a commit hash contains only valid hex characters
// and has a reasonable length (7-64 chars) to avoid ambiguous short refs.
func validateCommitHash(commit string) error {
	if commit == "" {
		return fmt.Errorf("empty commit hash")
	}
	if len(commit) < 7 || len(commit) > 64 {
		return fmt.Errorf("commit hash has invalid length %d (expected 7-64): %s", len(commit), commit)
	}
	for _, c := range commit {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return fmt.Errorf("commit hash contains invalid character %q: %s", c, commit)
		}
	}
	return nil
}

func extractImageTag(imageRef string) string {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return ""
	}
	if i := strings.Index(imageRef, "@"); i >= 0 {
		imageRef = imageRef[:i]
	}
	lastSlash := strings.LastIndex(imageRef, "/")
	lastColon := strings.LastIndex(imageRef, ":")
	if lastColon <= lastSlash {
		return ""
	}
	return imageRef[lastColon+1:]
}

// looksLikeSemverTag returns true if the tag looks like a version string
// (e.g., "v1.2.3", "1.45.0", "v3.9.1-rc1"). This prevents the image tag
// heuristic from trying non-version tags like "latest", "stable", or "alpine"
// as git refs.
func looksLikeSemverTag(tag string) bool {
	t := strings.TrimPrefix(tag, "v")
	if t == "" {
		return false
	}
	// Must start with a digit and contain at least one dot (e.g., "1.2")
	if t[0] < '0' || t[0] > '9' {
		return false
	}
	return strings.Contains(t, ".")
}

func parseGoVCSURL(goVCSURL string) (string, string, error) {
	if goVCSURL == "" {
		return "", "", fmt.Errorf("go-vcs-url is empty")
	}
	i := strings.LastIndex(goVCSURL, "@")
	if i <= 0 || i >= len(goVCSURL)-1 {
		return "", "", fmt.Errorf("invalid go-vcs-url format, expected repo@ref")
	}
	repoURL := goVCSURL[:i]
	ref := goVCSURL[i+1:]
	if err := validateRepoURL(repoURL); err != nil {
		return "", "", err
	}
	if err := validateShellSafeStrict(ref, "go-vcs-url ref"); err != nil {
		return "", "", err
	}
	return repoURL, ref, nil
}

// cloneSourceCode clones the source repository using BuildKit Git LLB.
func (r *Rebuilder) cloneSourceCode(buildInfo *BuildInfo, rebuildCtx *RebuildContext) (llb.State, string, error) {
	repoURL := buildInfo.BuildArgs["_sourceRepo"]
	commit := buildInfo.BuildArgs["_sourceCommit"]
	subpath := ""
	ref := ""

	var overrideRepoURL, overrideRef string
	if rebuildCtx != nil && rebuildCtx.GoVCSURL != "" {
		var err error
		overrideRepoURL, overrideRef, err = parseGoVCSURL(rebuildCtx.GoVCSURL)
		if err != nil {
			return llb.State{}, "", fmt.Errorf("invalid go-vcs-url override: %w", err)
		}
	}

	derivedURL := ""
	derivedSubpath := ""
	if buildInfo.ModulePath != "" {
		derivedURL, derivedSubpath = deriveRepoFromModulePath(buildInfo.ModulePath)
		// Strip Go major version suffixes (v2, v3, ...) since these are module path
		// conventions, not actual subdirectories in most repositories.
		subpath = stripGoMajorVersionSuffix(derivedSubpath)
		if derivedURL != "" {
			log.Infof("Derived source repository from module path: %s (subpath: %q)", derivedURL, subpath)
		}
	}

	switch {
	case overrideRepoURL != "":
		repoURL = overrideRepoURL
		ref = overrideRef
		if err := validateRepoURL(repoURL); err != nil {
			return llb.State{}, "", err
		}
		log.Infof("Using --go-vcs-url override: %s @ %s", repoURL, ref)
	case commit != "":
		if err := validateCommitHash(commit); err != nil {
			return llb.State{}, "", fmt.Errorf("invalid source commit: %w", err)
		}
		if repoURL == "" {
			repoURL = derivedURL
		}
		if repoURL == "" {
			return llb.State{}, "", fmt.Errorf("no source repository URL in build info")
		}
		if err := validateRepoURL(repoURL); err != nil {
			return llb.State{}, "", err
		}
		ref = commit
		log.Infof("Cloning source from binary VCS metadata %s @ %s", repoURL, ref)
	case rebuildCtx != nil && rebuildCtx.ImageSourceLabel != "":
		// Step 3: OCI label org.opencontainers.image.source provides the source repo.
		// Combine with image tag as the git ref.
		labelURL := rebuildCtx.ImageSourceLabel
		if !strings.HasPrefix(labelURL, "https://github.com/") {
			return llb.State{}, "", fmt.Errorf("OCI source label URL not on github.com: %s", labelURL)
		}
		if err := validateRepoURL(labelURL); err != nil {
			return llb.State{}, "", fmt.Errorf("invalid OCI source label URL: %w", err)
		}
		tag := ""
		if rebuildCtx.ImageRef != "" {
			tag = extractImageTag(rebuildCtx.ImageRef)
		}
		if tag == "" || !looksLikeSemverTag(tag) {
			return llb.State{}, "", fmt.Errorf("OCI source label found (%s) but image has no semver tag for git ref", labelURL)
		}
		if err := validateShellSafeStrict(tag, "image tag"); err != nil {
			return llb.State{}, "", fmt.Errorf("invalid image tag: %w", err)
		}
		repoURL = labelURL
		ref = tag
		log.Infof("Using OCI source label %s @ %s (from org.opencontainers.image.source)", repoURL, ref)
	default:
		// Step 4: Image tag heuristic — derive repo from module path, use image tag as ref.
		tag := ""
		if rebuildCtx != nil {
			tag = extractImageTag(rebuildCtx.ImageRef)
		}
		if tag == "" || !looksLikeSemverTag(tag) {
			if repoURL != "" {
				log.Warnf("No commit/tag specified for %s - skipping clone", repoURL)
			}
			return llb.State{}, "", fmt.Errorf("no commit/tag specified for source clone")
		}
		if err := validateShellSafeStrict(tag, "image tag"); err != nil {
			return llb.State{}, "", fmt.Errorf("invalid image tag for source clone: %w", err)
		}
		if repoURL == "" {
			repoURL = derivedURL
		}
		if repoURL == "" {
			return llb.State{}, "", fmt.Errorf("no source repository URL in build info")
		}
		if err := validateRepoURL(repoURL); err != nil {
			return llb.State{}, "", err
		}
		ref = tag
		log.Infof("Cloning source using image tag fallback %s @ %s", repoURL, ref)
	}

	if repoURL == "" {
		return llb.State{}, "", fmt.Errorf("no source repository URL in build info")
	}

	gitRef := repoURL
	if !strings.HasSuffix(gitRef, ".git") {
		gitRef += ".git"
	}
	if ref != "" {
		gitRef += "#" + ref
	}

	gitState := llb.Git(gitRef, ref, llb.KeepGitDir())
	log.Debugf("Created Git LLB state for %s", gitRef)
	return gitState, subpath, nil
}

// retryScript generates a shell script that retries a command with exponential backoff.
// It retries up to maxRetries times with delays of 1s, 2s, 4s, etc.
func retryScript(cmd string, maxRetries int) string {
	return fmt.Sprintf(`
retry=0
max_retry=%d
until %s; do
    retry=$((retry+1))
    if [ $retry -ge $max_retry ]; then
        echo "Command failed after $max_retry attempts: %s"
        exit 1
    fi
    delay=$((1 << (retry - 1)))
    echo "Attempt $retry failed, retrying in ${delay}s..."
    sleep $delay
done
`, maxRetries, cmd, strings.ReplaceAll(cmd, `"`, `\"`))
}

// buildBinaryWithUpdates creates a BuildKit LLB state that rebuilds the binary.
func (r *Rebuilder) buildBinaryWithUpdates(
	baseImage string,
	rebuildCtx *RebuildContext,
	buildInfo *BuildInfo,
	updates map[string]string,
	platform *specs.Platform,
	outputPath string,
) (llb.State, error) {
	log.Debugf("Building binary with base image: %s, output path: %s", baseImage, outputPath)
	log.Debugf("Build info: module=%s, Go=%s, CGO=%v", buildInfo.ModulePath, buildInfo.GoVersion, buildInfo.CGOEnabled)

	var state llb.State
	if platform != nil {
		log.Debugf("Using platform: %s/%s", platform.OS, platform.Architecture)
		state = llb.Image(baseImage, llb.Platform(*platform))
	} else {
		state = llb.Image(baseImage)
	}

	workdir := "/build"
	if buildInfo.Workdir != "" {
		workdir = buildInfo.Workdir
	}

	// Try to clone source code from Git
	sourceCloned := false
	sourceState, subpath, err := r.cloneSourceCode(buildInfo, rebuildCtx)
	if err == nil {
		state = state.File(
			llb.Copy(sourceState, "/", workdir, &llb.CopyInfo{
				CreateDestPath: true,
			}),
		)
		sourceCloned = true
		if subpath != "" {
			workdir = filepath.Join(workdir, subpath)
			log.Infof("Cloned source code from Git repository, using subpath: %s", subpath)
		} else {
			log.Info("Cloned source code from Git repository")
		}
	} else {
		log.Warnf("Could not clone source code: %v", err)
		log.Warnf("Cannot rebuild Go binary without source — original binary will be preserved")
		return llb.State{}, errSourceNotCloned
	}

	state = state.Dir(workdir)
	log.Debugf("Working directory: %s", workdir)

	// Source was cloned successfully (early return above if not).

	goBin := "/usr/local/go/bin/go"

	// Install git (needed for go mod download)
	state = state.Run(
		llb.Args([]string{"sh", "-c", "apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*"}),
	).Root()

	// Download dependencies with retry (network can be flaky)
	downloadCmd := fmt.Sprintf("%s mod download -x", goBin)
	downloadScript := retryScript(downloadCmd, 3)
	log.Debug("Running go mod download with retry...")
	state = state.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(downloadScript, "'", "'\"'\"'"))),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Apply updates with retry for each module.
	// Validate module names and versions before constructing shell commands to prevent injection.
	for module, version := range updates {
		if err := validateGoModuleName(module); err != nil {
			return llb.State{}, err
		}
		if strings.ContainsAny(version, ";&|`$(){}[]<>\"'\\*?!~# \t\n\r") {
			return llb.State{}, fmt.Errorf("version contains unsafe characters: %s for module %s", version, module)
		}
		normalizedVersion := normalizeVersion(version)
		log.Infof("Updating module %s: %s -> %s", module, buildInfo.Dependencies[module], normalizedVersion)

		getCmd := fmt.Sprintf("%s get %s@%s", goBin, module, normalizedVersion)
		getScript := retryScript(getCmd, 3)
		state = state.Run(
			llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(getScript, "'", "'\"'\"'"))),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// Run mod tidy to sync go.sum after dependency updates.
	// This is needed both for generated go.mod and for cloned source where
	// go get may have added transitive dependencies not in the original go.sum.
	{
		log.Debug("Running go mod tidy...")
		state = state.Run(
			llb.Shlexf("%s mod tidy", goBin),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// If source was cloned (may have vendor/), sync vendor directory to match updated go.mod.
	// This prevents "inconsistent vendoring" errors when the project uses vendored dependencies.
	// We check for vendor/modules.txt existence and run `go mod vendor` if found.
	if sourceCloned {
		log.Debug("Checking for vendor directory and syncing if present...")
		vendorSyncScript := fmt.Sprintf(`
if [ -f vendor/modules.txt ]; then
    echo "Vendor directory detected, running go mod vendor..."
    %s mod vendor
else
    echo "No vendor directory found, skipping vendor sync"
fi
`, goBin)
		state = state.Run(
			llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(vendorSyncScript, "'", "'\"'\"'"))),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}

	// Create output directory
	outputDir := filepath.Dir(outputPath)
	log.Debugf("Creating output directory: %s", outputDir)
	state = state.File(llb.Mkdir(outputDir, 0o755, llb.WithParents(true)))

	// Build the binary. When source is cloned, use the discovery script to find
	// the correct main package directory (handles monorepos, non-standard layouts,
	// and binary name mismatches). Otherwise, run the build command directly.
	buildPrefix, mainPkg, err := r.constructBuildCommandParts(buildInfo, goBin, outputPath)
	if err != nil {
		return llb.State{}, fmt.Errorf("unsafe build command: %w", err)
	}

	// Source is always cloned at this point (early return above if not).
	binaryName := filepath.Base(outputPath)
	log.Infof("Using discovery+build script for %s (explicit pkg: %s)", binaryName, mainPkg)

	// Write the build command prefix to a file so the discovery script can
	// read it without shell escaping issues (ldflags often contain quotes).
	state = state.File(
		llb.Mkfile("/tmp/copa_build_prefix", 0o644, []byte(buildPrefix)),
	)
	state = state.File(
		llb.Mkfile("/tmp/copa_discover_build.sh", 0o755, []byte(discoverAndBuildScript)),
	)
	state = state.Run(
		llb.Shlex(fmt.Sprintf("sh /tmp/copa_discover_build.sh %s %s %s", binaryName, outputPath, mainPkg)),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Verify the rebuilt binary is a valid Go binary.
	// If discovery or build failed, the LLB step above already failed —
	// this is a secondary check that the output is actually a Go binary.
	verifyScript := fmt.Sprintf(`
if ! %s version -m %s > /dev/null 2>&1; then
  echo "ERROR: rebuilt binary %s is not a valid Go binary"
  exit 1
fi
`, goBin, outputPath, outputPath)
	log.Debug("Verifying rebuilt binary...")
	state = state.File(
		llb.Mkfile("/tmp/copa_verify.sh", 0o755, []byte(verifyScript)),
	)
	state = state.Run(
		llb.Shlex("sh /tmp/copa_verify.sh"),
	).Root()

	return state, nil
}

// generateGoMod generates a go.mod file from build information.
func (r *Rebuilder) generateGoMod(buildInfo *BuildInfo, updates map[string]string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "module %s\n\n", buildInfo.ModulePath)

	// Normalize Go version to major.minor format (strip patch version)
	// e.g., "1.20.4" -> "1.20"
	goVersion := buildInfo.GoVersion
	if parts := strings.Split(goVersion, "."); len(parts) >= 2 {
		goVersion = parts[0] + "." + parts[1]
	}
	fmt.Fprintf(&sb, "go %s\n\n", goVersion)

	if len(buildInfo.Dependencies) > 0 || len(updates) > 0 {
		sb.WriteString("require (\n")

		for module, version := range buildInfo.Dependencies {
			if _, hasUpdate := updates[module]; hasUpdate {
				continue
			}
			if version == "v0.0.0" || version == "(devel)" {
				continue
			}
			fmt.Fprintf(&sb, "\t%s %s\n", module, version)
		}

		for module, version := range updates {
			fmt.Fprintf(&sb, "\t%s %s\n", module, normalizeVersion(version))
		}

		sb.WriteString(")\n")
	}

	return sb.String()
}

// constructBuildCommand constructs a go build command from build info.
func (r *Rebuilder) constructBuildCommand(buildInfo *BuildInfo, goBin string, outputPath string) (string, error) {
	prefix, mainPkg, err := r.constructBuildCommandParts(buildInfo, goBin, outputPath)
	if err != nil {
		return "", err
	}
	return prefix + " " + mainPkg, nil
}

// constructBuildCommandParts returns the build command prefix and main package separately.
// The prefix contains everything except the main package argument.
func (r *Rebuilder) constructBuildCommandParts(buildInfo *BuildInfo, goBin string, outputPath string) (string, string, error) {
	// Validate all values sourced from untrusted binary metadata before shell interpolation.
	if goos, ok := buildInfo.BuildArgs["GOOS"]; ok {
		if err := validateShellSafeStrict(goos, "GOOS"); err != nil {
			return "", "", err
		}
	}
	if goarch, ok := buildInfo.BuildArgs["GOARCH"]; ok {
		if err := validateShellSafeStrict(goarch, "GOARCH"); err != nil {
			return "", "", err
		}
	}
	for _, flag := range buildInfo.BuildFlags {
		if err := validateShellSafe(flag, "build flag"); err != nil {
			return "", "", err
		}
	}
	if buildInfo.MainPackage != "" {
		if err := validateShellSafeStrict(buildInfo.MainPackage, "main package"); err != nil {
			return "", "", err
		}
	}

	var parts []string

	if !buildInfo.CGOEnabled {
		parts = append(parts, "CGO_ENABLED=0")
	} else {
		parts = append(parts, "CGO_ENABLED=1")
	}

	if goos, ok := buildInfo.BuildArgs["GOOS"]; ok && goos != "" {
		parts = append(parts, fmt.Sprintf("GOOS=%s", goos))
	}
	if goarch, ok := buildInfo.BuildArgs["GOARCH"]; ok && goarch != "" {
		parts = append(parts, fmt.Sprintf("GOARCH=%s", goarch))
	}

	parts = append(parts, goBin, "build")

	if outputPath != "" {
		parts = append(parts, "-o", outputPath)
	}

	parts = append(parts, buildInfo.BuildFlags...)

	mainPkg := buildInfo.MainPackage
	if mainPkg == "" {
		mainPkg = "."
	}

	return strings.Join(parts, " "), mainPkg, nil
}

// String returns string representation of RebuildStrategy.
func (s RebuildStrategy) String() string {
	switch s {
	case RebuildStrategyAuto:
		return "auto"
	case RebuildStrategyHeuristic:
		return "heuristic"
	case RebuildStrategyNone:
		return "none"
	default:
		return "unknown"
	}
}
