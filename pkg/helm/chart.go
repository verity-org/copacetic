package helm

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmregistry "helm.sh/helm/v3/pkg/registry"
)

// DownloadChart downloads a Helm chart from the given repository at the specified version.
// It is a function variable to allow test injection without network access.
var DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
	tmpDir, err := os.MkdirTemp("", "copa-helm-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for chart download: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	settings := helmcli.New()

	registryClient, err := helmregistry.NewClient(
		helmregistry.ClientOptEnableCache(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm registry client: %w", err)
	}

	cfg := &helmaction.Configuration{
		RegistryClient: registryClient,
	}

	pull := helmaction.NewPullWithOpts(helmaction.WithConfig(cfg))
	pull.Settings = settings
	pull.Version = version
	pull.DestDir = tmpDir
	pull.Untar = false

	// For OCI repos, the full reference includes the chart name.
	// For HTTP repos, we set RepoURL separately.
	var chartRef string
	if strings.HasPrefix(repository, "oci://") {
		chartRef = strings.TrimSuffix(repository, "/") + "/" + name
	} else {
		pull.RepoURL = repository
		chartRef = name
	}

	output, err := pull.Run(chartRef)
	if err != nil {
		return nil, fmt.Errorf("failed to pull chart '%s' v%s from %s: %w", name, version, repository, err)
	}
	if output != "" {
		log.Debugf("helm pull output for '%s': %s", name, output)
	}

	// Locate the downloaded .tgz file in the temp dir
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read temp dir after chart pull: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no chart archive found after pulling '%s'", name)
	}

	chartPath := tmpDir + "/" + entries[0].Name()
	ch, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart archive '%s': %w", chartPath, err)
	}

	return ch, nil
}

// RenderChart renders a Helm chart to Kubernetes manifests using default values.
// It is a function variable to allow test injection.
var RenderChart = func(ch *helmchart.Chart) (string, error) {
	settings := helmcli.New()
	cfg := &helmaction.Configuration{}
	// Initialize with no-op debug log to suppress Helm's internal logging
	if err := cfg.Init(settings.RESTClientGetter(), "default", "memory", func(_ string, _ ...interface{}) {}); err != nil {
		// If Init fails (no kubeconfig in test/CI), we still continue since ClientOnly mode
		// does not require a real cluster connection. Log and proceed.
		log.Debugf("helm: cfg.Init failed (expected in no-cluster environments): %v", err)
	}

	install := helmaction.NewInstall(cfg)
	install.DryRun = true
	install.ClientOnly = true
	install.Replace = true
	install.ReleaseName = ch.Metadata.Name
	install.Namespace = "default"
	install.IncludeCRDs = true

	release, err := install.Run(ch, map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("failed to render chart '%s': %w", ch.Metadata.Name, err)
	}

	return release.Manifest, nil
}

// DiscoverChartImages downloads, renders, and extracts all container images
// from a Helm chart. Overrides are applied to the discovered images.
// This is the primary entry point for chart-based image discovery.
func DiscoverChartImages(ch *helmchart.Chart, overrides map[string]OverrideSpec) ([]ChartImage, error) {
	rendered, err := RenderChart(ch)
	if err != nil {
		return nil, fmt.Errorf("failed to render chart '%s': %w", ch.Metadata.Name, err)
	}

	images, err := ExtractImages(rendered)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from chart '%s': %w", ch.Metadata.Name, err)
	}

	if len(images) == 0 {
		log.Warnf("helm: no container images found in chart '%s' — chart may be CRD-only or have all images in conditionally-disabled templates", ch.Metadata.Name)
		return images, nil
	}

	return ApplyOverrides(images, overrides), nil
}
