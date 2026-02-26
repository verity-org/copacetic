package langmgr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPipInstallTimeoutSeconds = 300
	pipCheckFile                    = "/copa-pip-check"
	sitePackagesDetectFile          = "/copa-site-packages-path"
	defaultToolingPythonTag         = "3-slim" // fallback tooling image tag if version can't be inferred
	toolingImageTemplate            = "docker.io/library/python:%s"
)

type pythonManager struct {
	config        *buildkit.Config
	workingFolder string
}

// validPythonPackageNamePattern defines the regex pattern for valid Python package names
// Based on PEP 508: https://www.python.org/dev/peps/pep-0508/
var validPythonPackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// validatePythonPackageName validates that a package name is safe for use in shell commands.
func validatePythonPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 214 {
		return fmt.Errorf("package name too long (max 214 characters)")
	}
	if !validPythonPackageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package name format: %s", name)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(name, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("package name contains unsafe characters: %s", name)
	}
	return nil
}

// validatePythonVersion validates that a version string is safe for use in shell commands.
func validatePythonVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	// Check if it's a valid PEP440 version
	if !isValidPythonVersion(version) {
		return fmt.Errorf("invalid version format: %s", version)
	}
	// Additional safety checks for shell injection
	if strings.ContainsAny(version, ";&|`$(){}[]<>\"'\\") {
		return fmt.Errorf("version contains unsafe characters: %s", version)
	}
	return nil
}

// isValidPythonVersion checks if a version string is a valid PEP440 version.
func isValidPythonVersion(v string) bool {
	_, err := pep440.Parse(v)
	return err == nil
}

// isLessThanPythonVersion compares two PEP440 version strings.
// It returns true if v1 is less than v2, and false if there's an error.
func isLessThanPythonVersion(v1, v2 string) bool {
	ver1, err1 := pep440.Parse(v1)
	if err1 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v1, err1)
		return false
	}
	ver2, err2 := pep440.Parse(v2)
	if err2 != nil {
		log.Warnf("Error parsing Python version '%s': %v", v2, err2)
		return false
	}
	return ver1.LessThan(ver2)
}

// validVenvRootPattern restricts venv root paths to safe filesystem characters,
// preventing shell metacharacter injection when the path is interpolated into commands.
var validVenvRootPattern = regexp.MustCompile(`^[A-Za-z0-9/_.\-~]+$`)

// validateVenvRoot ensures a venv root path contains only safe filesystem characters
// and cannot be used for shell command injection.
func validateVenvRoot(venvRoot string) error {
	if venvRoot == "" {
		return fmt.Errorf("venv root cannot be empty")
	}
	if !strings.HasPrefix(venvRoot, "/") {
		return fmt.Errorf("venv root must be an absolute path: %s", venvRoot)
	}
	if !validVenvRootPattern.MatchString(venvRoot) {
		return fmt.Errorf("venv root contains unsafe characters (shell metacharacters not allowed): %s", venvRoot)
	}
	return nil
}

// systemPythonPrefixes are path prefixes that are NOT virtual environments.
// Paths under these prefixes are treated as system Python installations.
var systemPythonPrefixes = []string{
	"/usr/lib/az", // Azure CLI custom Python path
	"/usr",        // covers /usr/lib/python* and /usr/local/lib/python*
}

// deriveVenvRoot extracts the venv root directory from a package PkgPath.
// For example: "opt/venv/lib/python3.12/site-packages" → "/opt/venv"
// Returns "" if the path is a system path or does not contain the expected pattern.
func deriveVenvRoot(pkgPath string) string {
	if pkgPath == "" {
		return ""
	}

	// Ensure leading slash.
	p := pkgPath
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// Find the /lib/pythonX.Y/site-packages segment.
	idx := strings.Index(p, "/lib/python")
	if idx == -1 {
		return ""
	}
	// Ensure site-packages follows (dist-packages for Debian is a system path).
	rest := p[idx:]
	if !strings.Contains(rest, "/site-packages") {
		return ""
	}

	prefix := p[:idx]
	if prefix == "" || prefix == "/" {
		return ""
	}

	for _, sys := range systemPythonPrefixes {
		if prefix == sys || strings.HasPrefix(prefix, sys+"/") {
			return ""
		}
	}

	return prefix
}

// groupPackagesByEnv separates packages into those belonging to the system Python
// installation and those residing in virtual environments.
// Returns:
//   - system: packages with no PkgPath or a system site-packages PkgPath
//   - venvs: map from venv root (e.g. "/opt/venv") to the packages found there
func groupPackagesByEnv(updates unversioned.LangUpdatePackages) (
	system unversioned.LangUpdatePackages,
	venvs map[string]unversioned.LangUpdatePackages,
) {
	venvs = make(map[string]unversioned.LangUpdatePackages)
	for _, pkg := range updates {
		root := deriveVenvRoot(pkg.PkgPath)
		if root == "" {
			system = append(system, pkg)
		} else {
			venvs[root] = append(venvs[root], pkg)
		}
	}
	return system, venvs
}

// filterPythonPackages returns only the packages that are Python packages.
func filterPythonPackages(langUpdates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var pythonPackages unversioned.LangUpdatePackages
	for _, pkg := range langUpdates {
		if pkg.Type == utils.PythonPackages {
			pythonPackages = append(pythonPackages, pkg)
		}
	}
	return pythonPackages
}

func (pm *pythonManager) InstallUpdates(
	ctx context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	var errPkgsReported []string // Packages that will be reported as problematic

	// Filter for Python packages only
	pythonUpdates := filterPythonPackages(manifest.LangUpdates)
	if len(pythonUpdates) == 0 {
		log.Debug("No Python packages found to update.")
		return currentState, []string{}, nil
	}

	pythonComparer := VersionComparer{isValidPythonVersion, isLessThanPythonVersion}
	updatesToAttempt, err := GetUniqueLatestUpdates(pythonUpdates, pythonComparer, ignoreErrors)
	if err != nil {
		// Collect error packages when GetUniqueLatestUpdates fails
		for _, u := range pythonUpdates {
			errPkgsReported = append(errPkgsReported, u.Name)
		}
		return currentState, errPkgsReported, fmt.Errorf("failed to determine unique latest Python updates: %w", err)
	}

	if len(updatesToAttempt) == 0 {
		log.Warn("No Python update packages were specified to apply.")
		return currentState, []string{}, nil
	}
	log.Debugf("Attempting to update latest unique pips: %v", updatesToAttempt)

	// Split packages by environment: system Python vs virtual environments.
	systemPkgs, venvPkgs := groupPackagesByEnv(updatesToAttempt)

	workingState := currentState

	// --- System Python packages ---
	if len(systemPkgs) > 0 {
		log.Debugf("Upgrading %d system Python package(s)", len(systemPkgs))
		updatedImageState, resultsBytes, upgradeErr := pm.upgradePackages(ctx, workingState, systemPkgs, ignoreErrors)
		if upgradeErr != nil {
			log.Errorf("Failed to upgrade system Python packages: %v.", upgradeErr)
			if !ignoreErrors {
				for _, u := range systemPkgs {
					errPkgsReported = append(errPkgsReported, u.Name)
				}
				return currentState, errPkgsReported, fmt.Errorf("python package upgrade operation failed: %w", upgradeErr)
			}
			log.Warnf("System Python package upgrade failed but errors are ignored.")
			for _, u := range systemPkgs {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
		} else {
			workingState = updatedImageState
			failedValidationPkgs, validationErr := pm.validatePythonPackageVersions(ctx, resultsBytes, systemPkgs, ignoreErrors)
			for _, pkgName := range failedValidationPkgs {
				if !slices.Contains(errPkgsReported, pkgName) {
					errPkgsReported = append(errPkgsReported, pkgName)
				}
			}
			if validationErr != nil {
				log.Warnf("System Python package validation issues: %v", validationErr)
				if !ignoreErrors {
					return workingState, errPkgsReported, fmt.Errorf("python package validation failed: %w", validationErr)
				}
			}
		}
	}

	// --- Virtual environment packages ---
	// Sort venv roots for deterministic ordering.
	var venvRoots []string
	for root := range venvPkgs {
		venvRoots = append(venvRoots, root)
	}
	sort.Strings(venvRoots)

	for _, venvRoot := range venvRoots {
		pkgs := venvPkgs[venvRoot]
		log.Infof("Upgrading %d Python package(s) in venv %s", len(pkgs), venvRoot)
		updatedImageState, resultsBytes, upgradeErr := pm.upgradeVenvPackages(ctx, workingState, venvRoot, pkgs, ignoreErrors)
		if upgradeErr != nil {
			log.Errorf("Failed to upgrade packages in venv %s: %v.", venvRoot, upgradeErr)
			if !ignoreErrors {
				for _, u := range pkgs {
					errPkgsReported = append(errPkgsReported, u.Name)
				}
				// Return workingState (not currentState) so any successfully applied
				// system package upgrades are preserved in the returned image state.
				return workingState, errPkgsReported, fmt.Errorf("venv %s package upgrade operation failed: %w", venvRoot, upgradeErr)
			}
			log.Warnf("Venv %s package upgrade failed but errors are ignored.", venvRoot)
			for _, u := range pkgs {
				errPkgsReported = append(errPkgsReported, u.Name)
			}
			continue
		}
		workingState = updatedImageState

		failedValidationPkgs, validationErr := pm.validatePythonPackageVersions(ctx, resultsBytes, pkgs, ignoreErrors)
		for _, pkgName := range failedValidationPkgs {
			if !slices.Contains(errPkgsReported, pkgName) {
				errPkgsReported = append(errPkgsReported, pkgName)
			}
		}
		if validationErr != nil {
			log.Warnf("Venv %s package validation issues: %v", venvRoot, validationErr)
			if !ignoreErrors {
				return workingState, errPkgsReported, fmt.Errorf("venv %s package validation failed: %w", venvRoot, validationErr)
			}
		}
	}

	if len(errPkgsReported) > 0 {
		log.Infof("Python packages reported as problematic (failed update or validation): %v", errPkgsReported)
	} else {
		log.Info("All Python packages successfully updated and validated.")
	}

	return workingState, errPkgsReported, nil
}

// validatePythonPackageVersions checks if the installed packages match the expected versions.
// resultsBytes: content of 'pip freeze' for the relevant packages.
// expectedUpdates: list of packages that were attempted to be updated.
// ignoreErrors: if true, validation failures are logged as warnings instead of returning an error.
func (pm *pythonManager) validatePythonPackageVersions(
	_ context.Context,
	resultsBytes []byte,
	expectedUpdates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) ([]string, error) {
	var failedPackages []string
	var validationIssues []string

	if resultsBytes == nil {
		if len(expectedUpdates) > 0 {
			log.Warn("validatePythonPackageVersions: resultsBytes is nil, cannot validate package versions.")
			for _, pkgUpdate := range expectedUpdates {
				failedPackages = append(failedPackages, pkgUpdate.Name)
				validationIssues = append(validationIssues, fmt.Sprintf("package %s: no freeze data to validate", pkgUpdate.Name))
			}
			if !ignoreErrors && len(failedPackages) > 0 {
				uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
				return uniqueFailedPkgsList, fmt.Errorf(
					"failed to validate python packages: %s", strings.Join(validationIssues, "; "))
			}
		}
		return failedPackages, nil
	}

	installedPkgs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(resultsBytes)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Handle strict package==version format first
		if parts := strings.SplitN(line, "==", 2); len(parts) == 2 {
			pkgName := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			installedPkgs[pkgName] = version
		} else {
			// Handle other formats that might be encountered in pip freeze output
			// Examples: "package>=1.0", "package~=1.0", etc.
			// For compatibility, we'll extract the package name but skip version parsing
			// since we only care about packages with exact version matches (==)
			log.Debugf("Skipping line without strict '==' format in pip freeze output: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading pip freeze results: %v", err)
		for _, pkgUpdate := range expectedUpdates {
			failedPackages = append(failedPackages, pkgUpdate.Name)
		}
		// Create a unique list of failed packages
		uniqueFailedPkgsList := utils.DeduplicateStringSlice(failedPackages)
		return uniqueFailedPkgsList, fmt.Errorf("error reading pip freeze results: %w", err)
	}

	for _, expectedPkg := range expectedUpdates {
		actualVersion, found := installedPkgs[expectedPkg.Name]
		if !found {
			errMsg := fmt.Sprintf("package %s was not found in pip freeze output after update attempt", expectedPkg.Name)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if !isValidPythonVersion(actualVersion) {
			errMsg := fmt.Sprintf("package %s has an invalid actual version format: %s", expectedPkg.Name, actualVersion)
			validationIssues = append(validationIssues, errMsg)
			failedPackages = append(failedPackages, expectedPkg.Name)
			log.Warnf("%s", errMsg)
			continue
		}

		if expectedPkg.FixedVersion != "" {
			if !isValidPythonVersion(expectedPkg.FixedVersion) {
				errMsg := fmt.Sprintf("package %s has an invalid expected fixed version format: %s",
					expectedPkg.Name, expectedPkg.FixedVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
				continue
			}

			vActual, _ := pep440.Parse(actualVersion)
			vExpected, _ := pep440.Parse(expectedPkg.FixedVersion)

			if !vActual.Equal(vExpected) {
				errMsg := fmt.Sprintf("package %s: expected version %s, but found %s",
					expectedPkg.Name, expectedPkg.FixedVersion, actualVersion)
				validationIssues = append(validationIssues, errMsg)
				failedPackages = append(failedPackages, expectedPkg.Name)
				log.Warnf("%s", errMsg)
			}
		} else {
			if expectedPkg.InstalledVersion != "" && isValidPythonVersion(expectedPkg.InstalledVersion) {
				vActual, _ := pep440.Parse(actualVersion)
				vInstalled, errInstalled := pep440.Parse(expectedPkg.InstalledVersion)
				if errInstalled == nil {
					switch {
					case vActual.LessThan(vInstalled):
						errMsg := fmt.Sprintf(
							"package %s: upgraded to version %s, which is older than installed version %s",
							expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
						validationIssues = append(validationIssues, errMsg)
						failedPackages = append(failedPackages, expectedPkg.Name)
						log.Warnf("%s", errMsg)
					case vActual.Equal(vInstalled):
						log.Infof("Package %s version %s remained unchanged after upgrade attempt.", expectedPkg.Name, actualVersion)
					default:
						log.Infof("Package %s successfully upgraded from %s to %s.",
							expectedPkg.Name, expectedPkg.InstalledVersion, actualVersion)
					}
				} else {
					log.Infof("Package %s updated to %s (InstalledVersion %s was not parsable for comparison).",
						expectedPkg.Name, actualVersion, expectedPkg.InstalledVersion)
				}
			} else {
				log.Infof("Package %s updated to %s (no valid InstalledVersion for comparison or no FixedVersion specified).",
					expectedPkg.Name, actualVersion)
			}
		}
	}

	var uniqueFailedPkgsList []string
	if len(failedPackages) > 0 {
		uniqueFailedPkgsList = utils.DeduplicateStringSlice(failedPackages)
	}

	if len(validationIssues) > 0 {
		summaryError := errors.New(strings.Join(validationIssues, "; "))
		if !ignoreErrors {
			return uniqueFailedPkgsList, summaryError
		}
		log.Warnf("Python package validation issues (ignored): %v", summaryError)
	}

	return uniqueFailedPkgsList, nil
}

func (pm *pythonManager) upgradePackages(
	ctx context.Context,
	currentState *llb.State,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	var installPkgSpecs []string
	for _, u := range updates {
		// Validate package name for security
		if err := validatePythonPackageName(u.Name); err != nil {
			log.Errorf("Invalid package name %s: %v", u.Name, err)
			if !ignoreErrors {
				return nil, nil, fmt.Errorf("package name validation failed for %s: %w", u.Name, err)
			}
			continue
		}

		if u.FixedVersion != "" {
			// Validate version for security
			if err := validatePythonVersion(u.FixedVersion); err != nil {
				log.Errorf("Invalid version %s for package %s: %v", u.FixedVersion, u.Name, err)
				if !ignoreErrors {
					return nil, nil, fmt.Errorf("version validation failed for %s: %w", u.Name, err)
				}
				continue
			}
			// Use validated package name and version to create spec
			installPkgSpecs = append(installPkgSpecs, u.Name+"=="+u.FixedVersion)
		}
	}

	if len(installPkgSpecs) == 0 {
		log.Info("No Python packages to install or upgrade.")
		return currentState, []byte{}, nil
	}

	// First, detect if pip (or pip3) exists in the target image. If not, use tooling container fallback.
	pipExists, detectErr := pm.detectPip(ctx, currentState)
	if detectErr != nil {
		log.Warnf("pip detection encountered an issue; proceeding assuming pip absent: %v", detectErr)
	}

	if !pipExists {
		log.Infof("pip not found in target image. Falling back to tooling container strategy for Python updates.")
		return pm.upgradePackagesWithTooling(ctx, currentState, installPkgSpecs)
	}

	// Install all requested update packages using validated package specifications directly in target image
	pipInstalled := pm.installPythonPackages(currentState, installPkgSpecs, ignoreErrors)

	// Write updates-manifest to host for post-patch validation (pip freeze)
	const outputResultsTemplate = `sh -c 'pip freeze --all > %s; if [ $? -ne 0 ]; then echo "WARN: pip freeze returned $?"; fi'`
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, resultManifest)
	mkFolders := pipInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(pipInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, err
	}
	return &pipInstalled, resultsBytes, nil
}

// installPythonPackages installs packages; if ignoreErrors is true, each package is attempted individually.
func (pm *pythonManager) installPythonPackages(currentState *llb.State, packageSpecs []string, ignoreErrors bool) llb.State {
	if len(packageSpecs) == 0 {
		return *currentState
	}
	if ignoreErrors {
		var installCommands []string
		for _, spec := range packageSpecs {
			installCommands = append(installCommands,
				fmt.Sprintf(`pip install --timeout %d '%s' || printf "WARN: pip install failed for %s\n"`,
					defaultPipInstallTimeoutSeconds, spec, spec))
		}
		installCmd := fmt.Sprintf(`sh -c '%s'`, strings.Join(installCommands, "; "))
		return currentState.Run(
			llb.Shlex(installCmd),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}
	// Standard single command install (fail-fast)
	args := []string{"pip", "install", fmt.Sprintf("--timeout=%d", defaultPipInstallTimeoutSeconds)}
	args = append(args, packageSpecs...)
	return currentState.Run(
		llb.Args(args),
		llb.WithProxy(utils.GetProxy()),
	).Root()
}

// detectPip checks if pip or pip3 exists in the target image by creating a marker file if found.
func (pm *pythonManager) detectPip(ctx context.Context, currentState *llb.State) (bool, error) {
	checkCmd := `sh -c 'if command -v pip >/dev/null 2>&1; then echo ok > ` + pipCheckFile + `; elif command -v pip3 >/dev/null 2>&1; then echo ok > ` + pipCheckFile + `; fi'`
	checked := currentState.Run(llb.Shlex(checkCmd)).Root()
	_, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &checked, pipCheckFile)
	if err != nil {
		// File not found implies pip absent; treat other errors the same for now
		return false, nil
	}
	return true, nil
}

// detectPipAt checks if a pip binary exists at the given absolute path in the image.
// pipPath is passed as a positional argument ($1) rather than interpolated into the
// script string, preventing shell injection.
func (pm *pythonManager) detectPipAt(ctx context.Context, currentState *llb.State, pipPath string) (bool, error) {
	// sh -c 'SCRIPT' -- "$1": $0 is set to "copa-check", $1 is pipPath.
	script := `if [ -x "$1" ]; then echo ok > ` + pipCheckFile + `; fi`
	checked := currentState.Run(llb.Args([]string{"sh", "-c", script, "copa-check", pipPath})).Root()
	_, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &checked, pipCheckFile)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// installPythonPackagesWithPip installs packages using a specific pip binary path.
// This mirrors installPythonPackages but parameterizes the pip executable.
func (pm *pythonManager) installPythonPackagesWithPip(currentState *llb.State, pipPath string, packageSpecs []string, ignoreErrors bool) llb.State {
	if len(packageSpecs) == 0 {
		return *currentState
	}
	if ignoreErrors {
		// Pass pipPath as $1 and each package spec as subsequent positional args to prevent
		// shell injection from pipPath being interpolated into the command string.
		script := fmt.Sprintf(
			`pip="$1"; shift; for s in "$@"; do "$pip" install --timeout %d "$s" || printf "WARN: pip install failed for %%s\n" "$s"; done`,
			defaultPipInstallTimeoutSeconds)
		args := []string{"sh", "-c", script, "copa-install", pipPath}
		args = append(args, packageSpecs...)
		return currentState.Run(
			llb.Args(args),
			llb.WithProxy(utils.GetProxy()),
		).Root()
	}
	args := []string{pipPath, "install", fmt.Sprintf("--timeout=%d", defaultPipInstallTimeoutSeconds)}
	args = append(args, packageSpecs...)
	return currentState.Run(
		llb.Args(args),
		llb.WithProxy(utils.GetProxy()),
	).Root()
}

// upgradeVenvPackages installs package upgrades in a specific virtual environment.
// It tries <venvRoot>/bin/pip first, then <venvRoot>/bin/pip3.
// If neither pip binary is found in the venv, it falls back to the tooling container
// strategy targeting <venvRoot>/lib/python*/site-packages/.
func (pm *pythonManager) upgradeVenvPackages(
	ctx context.Context,
	currentState *llb.State,
	venvRoot string,
	updates unversioned.LangUpdatePackages,
	ignoreErrors bool,
) (*llb.State, []byte, error) {
	// Validate venvRoot before using it in any shell command to prevent injection.
	if err := validateVenvRoot(venvRoot); err != nil {
		return nil, nil, fmt.Errorf("invalid venv root path: %w", err)
	}

	var installPkgSpecs []string
	for _, u := range updates {
		if err := validatePythonPackageName(u.Name); err != nil {
			log.Errorf("Invalid package name %s in venv %s: %v", u.Name, venvRoot, err)
			if !ignoreErrors {
				return nil, nil, fmt.Errorf("package name validation failed for %s: %w", u.Name, err)
			}
			continue
		}
		if u.FixedVersion != "" {
			if err := validatePythonVersion(u.FixedVersion); err != nil {
				log.Errorf("Invalid version %s for package %s in venv %s: %v", u.FixedVersion, u.Name, venvRoot, err)
				if !ignoreErrors {
					return nil, nil, fmt.Errorf("version validation failed for %s: %w", u.Name, err)
				}
				continue
			}
			installPkgSpecs = append(installPkgSpecs, u.Name+"=="+u.FixedVersion)
		}
	}
	if len(installPkgSpecs) == 0 {
		return currentState, []byte{}, nil
	}

	// Locate pip inside the venv.
	pipPath := ""
	for _, candidate := range []string{venvRoot + "/bin/pip", venvRoot + "/bin/pip3"} {
		exists, err := pm.detectPipAt(ctx, currentState, candidate)
		if err != nil {
			log.Warnf("Error checking for pip at %s: %v", candidate, err)
		}
		if exists {
			pipPath = candidate
			break
		}
	}

	if pipPath == "" {
		// Fall back: use tooling container, target the venv's site-packages directory.
		log.Infof("No pip binary found in venv %s; falling back to tooling container strategy.", venvRoot)
		return pm.upgradeVenvPackagesWithTooling(ctx, currentState, venvRoot, installPkgSpecs)
	}

	log.Infof("[venv %s] Installing packages using %s: %v", venvRoot, pipPath, installPkgSpecs)
	pipInstalled := pm.installPythonPackagesWithPip(currentState, pipPath, installPkgSpecs, ignoreErrors)

	// Capture pip freeze for post-patch validation.
	// pipPath is passed as $1 to prevent shell injection.
	freezeScript := `"$1" freeze --all > ` + resultManifest + `; rc=$?; if [ $rc -ne 0 ]; then echo "WARN: pip freeze returned $rc"; fi`
	mkFolders := pipInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Args([]string{"sh", "-c", freezeScript, "copa-freeze", pipPath})).Root()
	resultsDiff := llb.Diff(pipInstalled, resultsWritten)

	resultsBytes, err := buildkit.ExtractFileFromState(ctx, pm.config.Client, &resultsDiff, filepath.Join(resultsPath, resultManifest))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to capture pip freeze for venv %s: %w", venvRoot, err)
	}
	return &pipInstalled, resultsBytes, nil
}

// upgradeVenvPackagesWithTooling is the fallback when no pip binary is found in a venv.
// It detects the venv's site-packages directory and uses a tooling container to install packages there.
func (pm *pythonManager) upgradeVenvPackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	venvRoot string,
	installPkgSpecs []string,
) (*llb.State, []byte, error) {
	// Detect site-packages directory inside the venv (glob for pythonX.Y).
	// venvRoot is validated by the caller (upgradeVenvPackages) before this point.
	// Pass it as a positional argument ($1) for defense-in-depth.
	detectScript := `for d in "$1"/lib/python*/site-packages; do if [ -d "$d" ]; then echo "$d" > ` + sitePackagesDetectFile + `; break; fi; done`
	detected := currentState.Run(llb.Args([]string{"sh", "-c", detectScript, "copa-detect", venvRoot})).Root()
	pathBytes, extractErr := buildkit.ExtractFileFromState(ctx, pm.config.Client, &detected, sitePackagesDetectFile)
	sitePkgsPath := strings.TrimSpace(string(pathBytes))
	if sitePkgsPath == "" {
		if extractErr != nil {
			return nil, nil, fmt.Errorf("unable to locate site-packages directory in venv %s: %w", venvRoot, extractErr)
		}
		return nil, nil, fmt.Errorf("unable to locate site-packages directory in venv %s", venvRoot)
	}
	log.Infof("Detected venv site-packages path: %s", sitePkgsPath)

	// Infer Python version from detected path.
	versionRegex := regexp.MustCompile(`python(\d+\.\d+)`)
	toolingTag := defaultToolingPythonTag
	if m := versionRegex.FindStringSubmatch(sitePkgsPath); len(m) == 2 {
		toolingTag = fmt.Sprintf("%s-slim", m[1])
	}
	toolingImage := fmt.Sprintf(toolingImageTemplate, toolingTag)
	log.Infof("Using tooling image %s for venv %s", toolingImage, venvRoot)

	// Use llb.Args to avoid shell interpolation of package specs.
	pipInstallArgs := []string{
		"pip", "install",
		"--no-cache-dir", "--disable-pip-version-check", "--no-deps",
		"--target", "/copa-pkgs",
	}
	pipInstallArgs = append(pipInstallArgs, installPkgSpecs...)
	toolingState := llb.Image(toolingImage).Run(
		llb.Args(pipInstallArgs),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Clean old package directories then copy the new ones in.
	var pkgBaseNames []string
	for _, spec := range installPkgSpecs {
		parts := strings.SplitN(spec, "==", 2)
		name := strings.ToLower(strings.ReplaceAll(parts[0], "_", "-"))
		pkgBaseNames = append(pkgBaseNames, name)
	}
	// Pass sitePkgsPath as $1 and package base names as subsequent positional args to
	// prevent injection from sitePkgsPath being interpolated into the shell command.
	cleanScript := `sp="$1"; shift; for p in "$@"; do rm -rf "$sp/$p" 2>/dev/null || true; for d in "$sp/$p"-*.dist-info; do [ -d "$d" ] && rm -rf "$d" || true; done; done`
	cleanArgs := []string{"sh", "-c", cleanScript, "clean-script", sitePkgsPath}
	cleanArgs = append(cleanArgs, pkgBaseNames...)
	cleaned := currentState.Run(llb.Args(cleanArgs)).Root()

	merged := cleaned.File(
		llb.Copy(toolingState, "/copa-pkgs/", sitePkgsPath+"/", &llb.CopyInfo{CopyDirContentsOnly: true, CreateDestPath: true}),
	)

	// Synthesize freeze-style results.
	var resultsLines []string
	for _, spec := range installPkgSpecs {
		if strings.Contains(spec, "==") {
			resultsLines = append(resultsLines, spec)
		}
	}
	resultsBytes := []byte(strings.Join(resultsLines, "\n"))
	return &merged, resultsBytes, nil
}

// upgradePackagesWithTooling performs Python package upgrades using an external tooling container when pip is absent in target image.
// Strategy:
// 1. Detect an appropriate site-packages directory in target image from a list of candidate paths.
// 2. Infer Python version from detected path (pattern pythonX.Y) to select a matching tooling image; fallback to default tag.
// 3. In tooling image, pip install packages into /copa-pkgs using --target (no deps, expect fixed versions).
// 4. Copy installed package contents into detected site-packages path in target image state.
// 5. Synthesize a pip freeze style resultsBytes for validation (package==version per line) since pip isn't present in target.
func (pm *pythonManager) upgradePackagesWithTooling(
	ctx context.Context,
	currentState *llb.State,
	installPkgSpecs []string,
) (*llb.State, []byte, error) {
	// Candidate site-packages paths (we'll choose the path that already contains the most target packages)
	candidatePaths := []string{
		"/usr/local/lib/python*/site-packages",
		"/usr/lib/python*/site-packages",
		"/opt/python*/site-packages",
		"/usr/lib/az/lib/python*/site-packages", // Az CLI custom path
	}

	// Build list of package base names (lowercase, normalize underscores to hyphens) for detection heuristics
	var pkgBaseNames []string
	for _, spec := range installPkgSpecs {
		parts := strings.SplitN(spec, "==", 2)
		name := parts[0]
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		pkgBaseNames = append(pkgBaseNames, name)
	}

	// Shell logic to pick directory with highest match count of existing packages
	detectScriptBuilder := strings.Builder{}
	detectScriptBuilder.WriteString("set -e; best=''; bestc=-1; pkgs=\"")
	for i, n := range pkgBaseNames {
		if i > 0 {
			detectScriptBuilder.WriteString(" ")
		}
		detectScriptBuilder.WriteString(n)
	}
	detectScriptBuilder.WriteString("\"; for pattern in")
	for _, p := range candidatePaths {
		fmt.Fprintf(&detectScriptBuilder, " '%s'", p)
	}
	detectScriptBuilder.WriteString("; do for d in $pattern; do [ -d \"$d\" ] || continue; c=0; for p in $pkgs; do if [ -d \"$d/$p\" ] || ls \"$d\" 2>/dev/null | grep -i -q \"^$p-.*\\.dist-info$\"; then c=$((c+1)); fi; done; if [ $c -gt $bestc ]; then bestc=$c; best=$d; fi; done; done; if [ -n \"$best\" ]; then echo $best > ") // nolint: lll
	detectScriptBuilder.WriteString(sitePackagesDetectFile)
	detectScriptBuilder.WriteString("; else for pattern in")
	for _, p := range candidatePaths {
		fmt.Fprintf(&detectScriptBuilder, " '%s'", p)
	}
	detectScriptBuilder.WriteString("; do for d in $pattern; do if [ -d \"$d\" ]; then echo $d > ")
	detectScriptBuilder.WriteString(sitePackagesDetectFile)
	detectScriptBuilder.WriteString("; exit 0; fi; done; done; fi")

	detectCmd := fmt.Sprintf("sh -c '%s'", detectScriptBuilder.String())
	detected := currentState.Run(llb.Shlex(detectCmd)).Root()
	pathBytes, _ := buildkit.ExtractFileFromState(ctx, pm.config.Client, &detected, sitePackagesDetectFile)
	sitePkgsPath := strings.TrimSpace(string(pathBytes))
	if sitePkgsPath == "" {
		return nil, nil, fmt.Errorf("unable to locate site-packages directory in target image (searched: %v)", candidatePaths)
	}
	log.Infof("Detected Python site-packages path: %s", sitePkgsPath)

	// Infer python version from path
	versionRegex := regexp.MustCompile(`python(\d+\.\d+)`)
	pyVersion := ""
	if m := versionRegex.FindStringSubmatch(sitePkgsPath); len(m) == 2 {
		pyVersion = m[1]
	}

	toolingTag := defaultToolingPythonTag
	if pyVersion != "" {
		// produce e.g. 3.12-slim
		toolingTag = fmt.Sprintf("%s-slim", pyVersion)
	}
	toolingImage := fmt.Sprintf(toolingImageTemplate, toolingTag)
	log.Infof("Using tooling image %s for Python package operations", toolingImage)

	// Build install command in tooling image
	toolingInstallCmd := fmt.Sprintf("sh -c 'pip install --no-cache-dir --disable-pip-version-check --no-deps --target /copa-pkgs %s'", strings.Join(installPkgSpecs, " "))
	toolingState := llb.Image(toolingImage).Run(
		llb.Shlex(toolingInstallCmd),
		llb.WithProxy(utils.GetProxy()),
	).Root()

	// Clean old versions of these packages in the detected site-packages path before copying new ones
	cleanScriptBuilder := strings.Builder{}
	cleanScriptBuilder.WriteString("set -e; sp=\"" + sitePkgsPath + "\"; pkgs=\"")
	for i, n := range pkgBaseNames {
		if i > 0 {
			cleanScriptBuilder.WriteString(" ")
		}
		cleanScriptBuilder.WriteString(n)
	}
	cleanScriptBuilder.WriteString("\"; if [ -n \"$pkgs\" ]; then for p in $pkgs; do rm -rf \"$sp/$p\" 2>/dev/null || true; for d in $sp/$p-*.dist-info; do [ -d \"$d\" ] && rm -rf \"$d\" || true; done; done; fi") // nolint: lll
	cleanCmd := fmt.Sprintf("sh -c '%s'", cleanScriptBuilder.String())
	cleaned := currentState.Run(llb.Shlex(cleanCmd)).Root()

	// Copy installed packages into target site-packages path after cleanup
	merged := cleaned.File(
		llb.Copy(toolingState, "/copa-pkgs/", sitePkgsPath+"/", &llb.CopyInfo{CopyDirContentsOnly: true, CreateDestPath: true}),
	)

	// Synthesize resultsBytes (freeze-like) from requested specs (only those with version pins)
	var resultsLines []string
	for _, spec := range installPkgSpecs {
		parts := strings.SplitN(spec, "==", 2)
		if len(parts) == 2 {
			resultsLines = append(resultsLines, spec)
		}
	}
	resultsBytes := []byte(strings.Join(resultsLines, "\n"))

	return &merged, resultsBytes, nil
}
