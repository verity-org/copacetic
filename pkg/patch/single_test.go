package patch

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type trackingReadCloser struct {
	closed bool
}

func (t *trackingReadCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

func TestPatchSingleArchImageRejectsInvalidReference(t *testing.T) {
	t.Parallel()

	result, err := patchSingleArchImage(context.Background(), &types.Options{Image: "not a valid reference"}, types.PatchPlatform{}, false, nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse reference")
}

func TestValidatePlatformEmulationAllowsHostPlatform(t *testing.T) {
	t.Parallel()

	host := platforms.Normalize(platforms.DefaultSpec())
	target := types.PatchPlatform{Platform: v1.Platform{OS: host.OS, Architecture: host.Architecture, Variant: host.Variant}}

	err := validatePlatformEmulation(target)

	assert.NoError(t, err)
}

func TestSetupWorkingFolderCreatesTemporaryDirectory(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder, cleanup, err := setupWorkingFolder("")
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	t.Cleanup(cleanup)

	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())

	cleanup()
	_, err = os.Stat(workingFolder)
	assert.ErrorIs(t, err, os.ErrNotExist)
	cleanup = func() {}
}

func TestSetupWorkingFolderHonorsExistingDirectoryWithoutRemovingIt(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder := t.TempDir()
	require.NoError(t, os.Chmod(workingFolder, 0o744))

	resolvedFolder, cleanup, err := setupWorkingFolder(workingFolder)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	assert.Equal(t, workingFolder, resolvedFolder)

	cleanup()
	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())
}

func TestSetupWorkingFolderCreatesExplicitDirectoryAndCleanupRemovesIt(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder := filepath.Join(t.TempDir(), "new-working-folder")

	resolvedFolder, cleanup, err := setupWorkingFolder(workingFolder)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	t.Cleanup(cleanup)
	assert.Equal(t, workingFolder, resolvedFolder)

	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())

	cleanup()
	_, err = os.Stat(workingFolder)
	assert.ErrorIs(t, err, os.ErrNotExist)
	cleanup = func() {}
}

func TestResolveImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
		expected string
	}{
		{
			name:     "name only defaults to latest",
			imageRef: "docker.io/library/alpine",
			expected: "docker.io/library/alpine:latest",
		},
		{
			name:     "tagged reference is preserved",
			imageRef: "docker.io/library/alpine:3.20",
			expected: "docker.io/library/alpine:3.20",
		},
		{
			name:     "digest reference is preserved",
			imageRef: "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imageName, err := reference.ParseNormalizedNamed(tt.imageRef)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, resolveImageReference(imageName))
		})
	}
}

func TestDetermineLoaderType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		loader   string
		bkAddr   string
		expected string
	}{
		{
			name:     "explicit loader wins over auto detection",
			loader:   imageloader.Podman,
			bkAddr:   "docker-container://builder0",
			expected: imageloader.Podman,
		},
		{
			name:     "auto detects docker from buildkit address",
			bkAddr:   "docker-container://builder0",
			expected: imageloader.Docker,
		},
		{
			name:     "unknown address leaves loader empty",
			bkAddr:   "tcp://buildkit.example:1234",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, determineLoaderType(tt.loader, tt.bkAddr))
		})
	}
}

func TestLoadImageToRuntimeReturnsLoaderCreationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pipe       io.ReadCloser
		assertFunc func(t *testing.T, err error)
	}{
		{
			name: "pipe reader closes with propagated error",
			pipe: func() io.ReadCloser {
				reader, writer := io.Pipe()
				_ = writer.Close()
				return reader
			}(),
			assertFunc: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create loader")
				assert.Contains(t, err.Error(), "unknown loader \"definitely-not-a-runtime\"")
			},
		},
		{
			name: "generic read closer is closed on error",
			pipe: &trackingReadCloser{},
			assertFunc: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create loader")
				assert.Contains(t, err.Error(), "unknown loader \"definitely-not-a-runtime\"")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := loadImageToRuntime(context.Background(), tt.pipe, "example.com/test:patched", "definitely-not-a-runtime")

			tt.assertFunc(t, err)
			if tracker, ok := tt.pipe.(*trackingReadCloser); ok {
				assert.True(t, tracker.closed)
			}
		})
	}
}

func TestCreatePatchResultWithStatesRejectsInvalidPatchedImageName(t *testing.T) {
	t.Parallel()

	imageName, err := reference.ParseNormalizedNamed("docker.io/library/alpine:3.20")
	require.NoError(t, err)

	result, err := createPatchResultWithStates(
		imageName,
		"Not A Valid Image Reference",
		&types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: "amd64"}},
		"docker.io/library/alpine:3.20",
		imageloader.Docker,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse patched image name")
}

func TestShouldIncludeUpdateTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		pkgTypes             []string
		expectOSUpdates      bool
		expectLibraryUpdates bool
	}{
		{
			name:                 "os only",
			pkgTypes:             []string{utils.PkgTypeOS},
			expectOSUpdates:      true,
			expectLibraryUpdates: false,
		},
		{
			name:                 "library only",
			pkgTypes:             []string{utils.PkgTypeLibrary},
			expectOSUpdates:      false,
			expectLibraryUpdates: true,
		},
		{
			name:                 "mixed package types",
			pkgTypes:             []string{utils.PkgTypeOS, utils.PkgTypeLibrary},
			expectOSUpdates:      true,
			expectLibraryUpdates: true,
		},
		{
			name:                 "empty package types",
			pkgTypes:             nil,
			expectOSUpdates:      false,
			expectLibraryUpdates: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expectOSUpdates, shouldIncludeOSUpdates(tt.pkgTypes))
			assert.Equal(t, tt.expectLibraryUpdates, shouldIncludeLibraryUpdates(tt.pkgTypes))
		})
	}
}

func TestValidateLibraryPkgTypesRequireReportSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		pkgTypes       []string
		reportProvided bool
		expectError    bool
	}{
		{
			name:           "os only does not require report",
			pkgTypes:       []string{utils.PkgTypeOS},
			reportProvided: false,
			expectError:    false,
		},
		{
			name:           "library requires report",
			pkgTypes:       []string{utils.PkgTypeLibrary},
			reportProvided: false,
			expectError:    true,
		},
		{
			name:           "library with report succeeds",
			pkgTypes:       []string{utils.PkgTypeOS, utils.PkgTypeLibrary},
			reportProvided: true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateLibraryPkgTypesRequireReport(tt.pkgTypes, tt.reportProvided)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "library package types require a scanner report file to be provided")
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestParsePkgTypesSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		expected    []string
		expectError bool
	}{
		{
			name:     "empty input defaults to os",
			input:    "",
			expected: []string{utils.PkgTypeOS},
		},
		{
			name:     "whitespace is trimmed",
			input:    " os , library ",
			expected: []string{utils.PkgTypeOS, utils.PkgTypeLibrary},
		},
		{
			name:     "duplicates are preserved in order",
			input:    "library,library,os",
			expected: []string{utils.PkgTypeLibrary, utils.PkgTypeLibrary, utils.PkgTypeOS},
		},
		{
			name:        "blank entry is rejected",
			input:       "os,,library",
			expectError: true,
		},
		{
			name:        "unknown value is rejected",
			input:       "os,application",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgTypes, err := parsePkgTypes(tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, pkgTypes)
				assert.Contains(t, err.Error(), "invalid package type")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, pkgTypes)
		})
	}
}

func TestCreateOriginalImageResultFallsBackWhenDescriptorLookupFails(t *testing.T) {
	t.Parallel()

	imageName, err := reference.ParseNormalizedNamed("docker.io/library/alpine:3.20")
	require.NoError(t, err)

	result, err := createOriginalImageResult(
		imageName,
		&types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: "amd64"}},
		"not a valid image reference",
	)

	require.NoError(t, err)
	assert.Equal(t, imageName.String(), result.OriginalRef.String())
	assert.Equal(t, imageName.String(), result.PatchedRef.String())
	assert.Nil(t, result.PatchedDesc)
}
