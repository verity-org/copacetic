package types

import "time"

// DisplayMode controls how BuildKit progress is rendered.
// Mirrors progressui.DisplayMode but defined here so consumers of pkg/types
// don't need to import moby/buildkit.
type DisplayMode string

const (
	AutoMode    DisplayMode = "auto"
	PlainMode   DisplayMode = "plain"
	TtyMode     DisplayMode = "tty"
	QuietMode   DisplayMode = "quiet"
	RawJSONMode DisplayMode = "rawjson"
)

// Options contains common copacetic options.
type Options struct {
	// Core single image patch configuration
	Image      string
	Report     string
	PatchedTag string
	Suffix     string

	// Bulk image patch configuration
	ConfigFile string
	DryRun     bool // Skip actual patching; run discovery and skip detection only

	// Working environment
	WorkingFolder string
	Timeout       time.Duration

	// Scanner and output
	Scanner     string
	IgnoreError bool

	// Output configuration
	Format     string
	Output     string
	OutputJSON string
	Progress   DisplayMode

	// Buildkit connection options
	BkAddr       string
	BkCACertPath string
	BkCertPath   string
	BkKeyPath    string

	// Platform and push
	Push      bool
	Platforms []string
	Loader    string
	OCIDir    string

	// Package types and library patch level
	PkgTypes          string
	LibraryPatchLevel string

	// Generate specific
	OutputContext string

	// EOL configuration
	EOLAPIBaseURL string
	ExitOnEOL     bool
}
