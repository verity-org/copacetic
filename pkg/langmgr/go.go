package langmgr

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
)

const (
	// goVersionMOutputFile is the temp path where go version -m output is stored.
	goVersionMOutputFile = "/copa-go-version-m-output"

	// toolingGoImageTemplate is the Docker image used as Go tooling container.
	toolingGoImageTemplate = "docker.io/library/golang:%s-alpine"

	// defaultGoToolingTag is the fallback when we can't detect the Go version.
	defaultGoToolingTag = "1"

	// shellUnsafeChars are characters that must not appear in values interpolated into shell commands.
	shellUnsafeChars = ";&|`$(){}[]<>\"'\\*?!~#\t\n\r"
)

// goManager implements LangManager for Go module/binary vulnerability patching.
type goManager struct {
	config        *buildkit.Config
	workingFolder string
	goVCSURL      string // --go-vcs-url flag value (format: repo@ref or just repo)
	imageRef      string // Container image reference for resolution chain
}

// filterGoPackages filters LangUpdatePackages to only include Go packages.
func filterGoPackages(langUpdates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var goPackages unversioned.LangUpdatePackages
	for _, pkg := range langUpdates {
		if pkg.Type == utils.GoModules || pkg.Type == utils.GoBinary {
			goPackages = append(goPackages, pkg)
		}
	}
	return goPackages
}

// isValidGoVersion checks if a version string is valid according to semver.
func isValidGoVersion(v string) bool {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return semver.IsValid(v)
}

// isLessThanGoVersion compares two Go version strings.
func isLessThanGoVersion(v1, v2 string) bool {
	if !strings.HasPrefix(v1, "v") {
		v1 = "v" + v1
	}
	if !strings.HasPrefix(v2, "v") {
		v2 = "v" + v2
	}
	return semver.Compare(v1, v2) < 0
}

// goVersionFromBuildInfo extracts a Docker tag-compatible Go version from GoBinaryInfo.
// e.g., "go1.25.5" → "1.25.5"
func goVersionFromBuildInfo(goVersion string) string {
	v := strings.TrimPrefix(goVersion, "go")
	if v == "" {
		return defaultGoToolingTag
	}
	return v
}

// InstallUpdates implements LangManager for Go packages.
// It detects Go binaries in the image, resolves their source code,
// and rebuilds them with updated dependencies.
func (gm *goManager) InstallUpdates(
	ctx context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgs []string

	goUpdates := filterGoPackages(manifest.LangUpdates)
	if len(goUpdates) == 0 {
		log.Debug("No Go packages found to update.")
		return currentState, nil, nil
	}

	log.Infof("Found %d Go package updates to process", len(goUpdates))

	// Deduplicate and get latest versions
	goComparer := VersionComparer{isValidGoVersion, isLessThanGoVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(goUpdates, goComparer, ignoreErrors)
	if err != nil {
		log.Errorf("Failed to determine unique latest Go updates: %v", err)
		if !ignoreErrors {
			return currentState, nil, fmt.Errorf("failed to determine unique Go updates: %w", err)
		}
	}

	if len(updatesToAttempt) == 0 {
		log.Debug("No Go update packages to apply after deduplication.")
		return currentState, nil, nil
	}

	// Build update map: module → version
	updateMap := make(map[string]string)
	for _, u := range updatesToAttempt {
		if u.FixedVersion == "" {
			continue
		}
		// Skip stdlib vulns — they require Go compiler upgrade
		if u.Name == "stdlib" {
			log.Warnf("Go stdlib vulnerability detected (needs Go compiler upgrade from %s to %s). Not supported in v1 — consider rebuilding the image with an updated Go version.",
				u.InstalledVersion, u.FixedVersion)
			continue
		}
		updateMap[u.Name] = u.FixedVersion
	}

	if len(updateMap) == 0 {
		log.Debug("No applicable Go module updates after filtering.")
		return currentState, nil, nil
	}

	log.Infof("Will update %d Go modules", len(updateMap))
	for mod, ver := range updateMap {
		log.Debugf("  %s → %s", mod, ver)
	}


	// Detect Go binaries in the image using go version -m
	binaries, detectErr := gm.detectGoBinaries(ctx, currentState)
	if detectErr != nil {
		log.Warnf("Failed to detect Go binaries in image: %v", detectErr)
		for mod := range updateMap {
			errPkgs = append(errPkgs, mod)
		}
		if !ignoreErrors {
			return currentState, errPkgs, fmt.Errorf("Go binary detection failed: %w", detectErr)
		}
		return currentState, errPkgs, nil
	}

	if len(binaries) == 0 {
		log.Warn("No Go binaries detected in image")
		return currentState, nil, nil
	}

	log.Infof("Detected %d Go binaries in image", len(binaries))

	// Process each binary
	state := *currentState
	rebuiltCount := 0

	for _, binary := range binaries {
		log.Infof("Processing binary: %s (%s, module: %s)", binary.Path, binary.GoVersion, binary.MainModule)

		// Skip CGO binaries
		if binary.CGOEnabled {
			log.Warnf("Skipping CGO-enabled binary %s: CGO rebuild not supported in v1", binary.Path)
			continue
		}

		// Check if this binary has any vulnerable deps
		binaryNeedsUpdate := false
		for mod := range updateMap {
			if binary.MainModule == mod || hasModule(binary.Deps, mod) {
				binaryNeedsUpdate = true
				break
			}
		}
		if !binaryNeedsUpdate {
			log.Debugf("Binary %s has no vulnerable dependencies, skipping", binary.Path)
			continue
		}

		// Resolve source code location
		resolution, resolveErr := resolveGoSource(binary, gm.imageRef, gm.goVCSURL)
		if resolveErr != nil {
			log.Warnf("Could not resolve source for binary %s: %v", binary.Path, resolveErr)
			errPkgs = append(errPkgs, binary.Path)
			if !ignoreErrors {
				return currentState, errPkgs, fmt.Errorf("source resolution failed for %s: %w", binary.Path, resolveErr)
			}
			continue
		}

		log.Infof("  Source resolved via %s: %s @ %s", resolution.Method, resolution.Repo, resolution.Ref)

		// Rebuild the binary
		newState, rebuildErr := gm.rebuildBinary(ctx, &state, binary, resolution, updateMap)
		if rebuildErr != nil {
			log.Warnf("Failed to rebuild binary %s: %v", binary.Path, rebuildErr)
			errPkgs = append(errPkgs, binary.Path)
			if !ignoreErrors {
				return currentState, errPkgs, fmt.Errorf("rebuild failed for %s: %w", binary.Path, rebuildErr)
			}
			continue
		}

		state = *newState
		rebuiltCount++
		log.Infof("  Successfully rebuilt binary: %s", binary.Path)
	}

	if rebuiltCount == 0 {
		log.Warn("No Go binaries were rebuilt")
	} else {
		log.Infof("Rebuilt %d Go binaries", rebuiltCount)
	}

	return &state, errPkgs, nil
}

// detectGoBinaries runs `go version -m` on all binaries in the image to find Go binaries.
func (gm *goManager) detectGoBinaries(ctx context.Context, currentState *llb.State) ([]*GoBinaryInfo, error) {
	// Use a Go tooling container to run `go version -m` on the target image's filesystem.
	// We mount the target image and scan for Go binaries.
	toolingImage := fmt.Sprintf(toolingGoImageTemplate, defaultGoToolingTag)

	// Script: find executable files, run go version -m on each, collect output
	detectScript := `find /target -type f -executable -not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/dev/*' 2>/dev/null | while read -r f; do go version -m "$f" 2>/dev/null; done > /output.txt; cat /output.txt`

	toolingState := llb.Image(toolingImage)
	// Copy the target image filesystem into /target in tooling container
	toolingState = toolingState.File(
		llb.Mkdir("/target", 0o755),
	)
	toolingState = toolingState.File(
		llb.Copy(*currentState, "/", "/target", &llb.CopyInfo{
			CopyDirContentsOnly: true,
			CreateDestPath:      true,
			AllowWildcard:       true,
		}),
	)

	// Run go version -m scan
	toolingState = toolingState.Run(
		llb.Args([]string{"sh", "-c", detectScript}),
		llb.WithProxy(buildkit.GetProxy()),
	).Root()

	// Extract the output
	outputBytes, err := buildkit.ExtractFileFromState(ctx, gm.config.Client, &toolingState, "/output.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to extract go version -m output: %w", err)
	}

	output := string(outputBytes)
	if strings.TrimSpace(output) == "" {
		return nil, nil
	}

	binaries, parseErr := parseGoBuildInfo(output)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse go version -m output: %w", parseErr)
	}

	// Fix binary paths: they'll have /target prefix from our mount
	for _, bi := range binaries {
		bi.Path = strings.TrimPrefix(bi.Path, "/target")
	}

	return binaries, nil
}

// rebuildBinary rebuilds a single Go binary with updated dependencies.
func (gm *goManager) rebuildBinary(
	ctx context.Context,
	currentState *llb.State,
	binary *GoBinaryInfo,
	resolution *GoSourceResolution,
	updateMap map[string]string,
) (*llb.State, error) {
	// Determine Go version for tooling container
	goVersion := goVersionFromBuildInfo(binary.GoVersion)
	toolingImage := fmt.Sprintf(toolingGoImageTemplate, goVersion)
	log.Debugf("Using tooling image: %s", toolingImage)

	// Validate inputs before shell interpolation
	if err := validateShellSafe(resolution.Repo, "repo URL"); err != nil {
		return nil, err
	}
	if err := validateShellSafe(resolution.Ref, "git ref"); err != nil {
		return nil, err
	}
	if err := validateShellSafe(binary.Path, "binary path"); err != nil {
		return nil, err
	}

	// Start with the tooling image
	var toolingState llb.State
	if gm.config.Platform != nil {
		toolingState = llb.Image(toolingImage, llb.Platform(*gm.config.Platform))
	} else {
		toolingState = llb.Image(toolingImage)
	}

	// Install git (needed for go get and source cloning)
	toolingState = toolingState.Run(
		llb.Args([]string{"apk", "add", "--no-cache", "git"}),
		llb.WithProxy(buildkit.GetProxy()),
	).Root()

	// Clone source repo
	cloneCmd := fmt.Sprintf("git clone --depth 1 --branch %s %s /src 2>&1 || git clone %s /src && cd /src && git checkout %s",
		resolution.Ref, resolution.Repo, resolution.Repo, resolution.Ref)
	toolingState = toolingState.Run(
		llb.Args([]string{"sh", "-c", cloneCmd}),
		llb.WithProxy(buildkit.GetProxy()),
	).Root()

	// Determine the build directory (subpath within the repo for the binary's main package)
	buildDir := determineBuildDir(binary)

	// Run go get for each updated module
	var getCommands []string
	for mod, ver := range updateMap {
		if strings.ContainsAny(mod, shellUnsafeChars) {
			return nil, fmt.Errorf("module name contains unsafe characters: %s", mod)
		}
		if strings.ContainsAny(ver, shellUnsafeChars) {
			return nil, fmt.Errorf("version contains unsafe characters: %s for module %s", ver, mod)
		}
		// Ensure version has v prefix
		if !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		getCommands = append(getCommands, fmt.Sprintf("go get %s@%s", mod, ver))
	}

	if len(getCommands) > 0 {
		updateCmd := fmt.Sprintf("cd /src/%s && %s && go mod tidy", buildDir, strings.Join(getCommands, " && "))
		toolingState = toolingState.Run(
			llb.Args([]string{"sh", "-c", updateCmd}),
			llb.WithProxy(buildkit.GetProxy()),
		).Root()
	}

	// Reconstruct the build command from original build settings
	buildCmd := constructGoBuildCommand(binary, buildDir)
	toolingState = toolingState.Run(
		llb.Args([]string{"sh", "-c", buildCmd}),
		llb.WithProxy(buildkit.GetProxy()),
	).Root()

	// Copy the rebuilt binary back to the target image
	state := currentState.File(
		llb.Copy(toolingState, "/output/binary", binary.Path, &llb.CopyInfo{
			CreateDestPath: true,
		}),
	)

	return &state, nil
}

// determineBuildDir determines the subdirectory within the repo to build from.
func determineBuildDir(binary *GoBinaryInfo) string {
	if binary.MainPath == "" || binary.MainPath == "command-line-arguments" {
		return "."
	}

	// The MainPath is the full import path (e.g., "github.com/prometheus/prometheus/cmd/prometheus")
	// The MainModule is the module root (e.g., "github.com/prometheus/prometheus")
	// The build dir is the relative path: "cmd/prometheus"
	mainPath := binary.MainPath
	mainModule := binary.MainModule

	if mainModule != "" && strings.HasPrefix(mainPath, mainModule+"/") {
		return strings.TrimPrefix(mainPath, mainModule+"/")
	}

	// Fallback: use the last path component as a guess
	return "."
}

// constructGoBuildCommand builds the go build command from the binary's build settings.
func constructGoBuildCommand(binary *GoBinaryInfo, buildDir string) string {
	parts := []string{"cd /src/" + buildDir}

	// Start with base build command
	buildArgs := []string{"go", "build", "-o", "/output/binary"}

	// Reconstruct build flags from settings
	if ldflags, ok := binary.BuildSettings["-ldflags"]; ok && ldflags != "" {
		buildArgs = append(buildArgs, fmt.Sprintf("-ldflags=%s", ldflags))
	}
	if tags, ok := binary.BuildSettings["-tags"]; ok && tags != "" {
		buildArgs = append(buildArgs, fmt.Sprintf("-tags=%s", tags))
	}
	if _, ok := binary.BuildSettings["-trimpath"]; ok {
		buildArgs = append(buildArgs, "-trimpath")
	}

	// Set CGO_ENABLED=0 (we skip CGO binaries, so this is always 0)
	env := "CGO_ENABLED=0"
	if goos, ok := binary.BuildSettings["GOOS"]; ok {
		env += " GOOS=" + goos
	}
	if goarch, ok := binary.BuildSettings["GOARCH"]; ok {
		env += " GOARCH=" + goarch
	}

	buildArgs = append(buildArgs, ".")
	parts = append(parts, fmt.Sprintf("mkdir -p /output && %s %s", env, strings.Join(buildArgs, " ")))

	return strings.Join(parts, " && ")
}

// hasModule checks if a dependency list contains a specific module.
func hasModule(deps []ModuleInfo, modulePath string) bool {
	for _, dep := range deps {
		if dep.Path == modulePath {
			return true
		}
	}
	return false
}

// validateShellSafe validates that a string doesn't contain shell injection characters.
func validateShellSafe(value, label string) error {
	if strings.ContainsAny(value, shellUnsafeChars) {
		return fmt.Errorf("%s contains unsafe characters: %s", label, value)
	}
	return nil
}
