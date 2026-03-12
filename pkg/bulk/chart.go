package bulk

import (
	"context"
	"fmt"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
)

// patchImage is the function used to patch a single image. It defaults to patch.Patch
// and can be overridden in tests.
var patchImage = func(ctx context.Context, opts *types.Options) error {
	return patch.Patch(ctx, opts)
}

// PatchChart orchestrates patching all images discovered from a single Helm chart
// and generating a patched wrapper chart pushed to an OCI registry.
//
// Flow:
//  1. Download and render the chart to discover container images
//  2. Patch each discovered image using the existing single-image patching flow
//  3. Build a wrapper chart with patched image overrides
//  4. Push the wrapper chart to the configured OCI registry
func PatchChart(ctx context.Context, opts *types.Options) error {
	if err := validateChartOpts(opts); err != nil {
		return err
	}

	chartSpec := ChartSpec{
		Name:       opts.ChartName,
		Version:    opts.ChartVersion,
		Repository: opts.ChartRepo,
	}

	// Step 1: Download chart and discover images.
	log.Infof("Downloading Helm chart '%s' v%s from %s...", chartSpec.Name, chartSpec.Version, chartSpec.Repository)
	charts := []ChartSpec{chartSpec}
	imageSpecs, resolutions, err := resolveChartImagesWithCharts(ctx, charts, nil)
	if err != nil {
		return fmt.Errorf("failed to resolve chart images: %w", err)
	}
	if len(imageSpecs) == 0 {
		log.Warn("No container images found in chart, nothing to patch.")
		return nil
	}
	if len(resolutions) == 0 {
		return fmt.Errorf("chart '%s' could not be downloaded or rendered", chartSpec.Name)
	}

	res := resolutions[0]
	log.Infof("Discovered %d image(s) in chart '%s'", len(res.Images), chartSpec.Name)

	// Step 2: Patch each discovered image sequentially.
	target := TargetSpec{
		Registry: opts.ChartRegistry, // Reuse chart registry as image target when no explicit target
	}
	// If the user provided a separate image target registry, use it; otherwise images go
	// to the same registry domain as the chart (this is a reasonable default).

	var mappings []chartImageMapping
	for _, img := range res.Images {
		imageWithTag := fmt.Sprintf("%s:%s", img.Repository, img.Tag)

		targetRepo, err := buildTargetRepository(img.Repository, target.Registry)
		if err != nil {
			log.Errorf("Failed to build target repository for '%s': %v", img.Repository, err)
			if !opts.IgnoreError {
				return fmt.Errorf("failed to build target repository for '%s': %w", img.Repository, err)
			}
			continue
		}

		targetTag, err := resolveTargetTag(target, img.Tag)
		if err != nil {
			log.Errorf("Failed to resolve target tag for '%s:%s': %v", img.Repository, img.Tag, err)
			if !opts.IgnoreError {
				return fmt.Errorf("failed to resolve target tag for '%s:%s': %w", img.Repository, img.Tag, err)
			}
			continue
		}

		patchedImageRef := fmt.Sprintf("%s:%s", targetRepo, targetTag)

		log.Infof("Patching image %s → %s...", imageWithTag, patchedImageRef)

		// Build per-image options — shallow copy the global options and override image-specific fields.
		jobOpts := *opts
		jobOpts.Image = imageWithTag
		jobOpts.PatchedTag = patchedImageRef
		jobOpts.Suffix = ""

		if err := patchImage(ctx, &jobOpts); err != nil {
			log.Errorf("Failed to patch %s: %v", imageWithTag, err)
			if !opts.IgnoreError {
				return fmt.Errorf("failed to patch %s: %w", imageWithTag, err)
			}
			continue
		}

		log.Infof("Successfully patched %s → %s", imageWithTag, patchedImageRef)
		mappings = append(mappings, chartImageMapping{
			ChartName:    chartSpec.Name,
			OriginalRepo: img.Repository,
			OriginalTag:  img.Tag,
			PatchedRepo:  targetRepo,
			PatchedTag:   targetTag,
		})
	}

	if len(mappings) == 0 {
		log.Warn("No images were successfully patched, skipping patched chart generation.")
		return nil
	}

	// Step 3: Generate and push the patched wrapper chart.
	config := PatchConfig{
		ChartTarget: &ChartTargetSpec{Registry: opts.ChartRegistry},
	}
	if err := generateAndPushPatchedCharts(resolutions, mappings, config); err != nil {
		return fmt.Errorf("failed to generate/push patched chart: %w", err)
	}

	return nil
}

// validateChartOpts validates the options required for single chart patching.
func validateChartOpts(opts *types.Options) error {
	if opts.ChartName == "" {
		return fmt.Errorf("chart name is required")
	}
	if opts.ChartVersion == "" {
		return fmt.Errorf("chart version is required")
	}
	if opts.ChartRepo == "" {
		return fmt.Errorf("chart repository is required")
	}
	if opts.ChartRegistry == "" {
		return fmt.Errorf("chart registry is required (--chart-registry)")
	}
	if !strings.HasPrefix(opts.ChartRegistry, "oci://") {
		return fmt.Errorf("chart registry must start with 'oci://' (got %q)", opts.ChartRegistry)
	}
	return nil
}
