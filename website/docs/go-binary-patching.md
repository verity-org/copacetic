---
title: Go Binary Patching
---

# Go Binary Patching

Copa can patch Go module and binary vulnerabilities in container images by rebuilding Go binaries from source with updated dependencies.

:::caution Experimental
Go binary patching requires `COPA_EXPERIMENTAL=1` and `--pkg-types library` (or `os,library`).
:::

## How It Works

1. **Scan**: Trivy detects vulnerable Go dependencies in compiled binaries (`gobinary`) or `go.sum` files (`gomod`)
2. **Detect**: Copa extracts build info from Go binaries using `go version -m` (embedded since Go 1.18)
3. **Resolve**: Copa finds the source code using a 3-step resolution chain
4. **Rebuild**: Copa clones the source, updates vulnerable deps with `go get`, and rebuilds the binary
5. **Replace**: The rebuilt binary replaces the original in the container image

## Source Resolution Chain

Copa uses three methods to find source code, tried in order:

### 1. Auto-detect (VCS info from binary)

If the binary was built with `go build` and `.git` was available at build time, the VCS commit hash is embedded. Copa uses this to clone the exact source.

**Works for**: Prometheus, Cilium, Istio, etcd, HashiCorp vault-k8s, and most well-maintained Go projects (~47% of images).

### 2. Tag Heuristic

If no VCS info is embedded, Copa derives the Git repo URL from the Go module path and tries the image tag as a Git ref.

For example: `docker.io/calico/cni:v3.31.4` with module `github.com/projectcalico/calico` → tries `https://github.com/projectcalico/calico` at tag `v3.31.4`.

**Works for**: Images where the tag matches a Git tag, even if VCS info was stripped.

### 3. `--go-vcs-url` Override

For the rare cases where both auto-detection and tag heuristic fail, you can provide the source URL directly:

```bash
# With explicit ref
--go-vcs-url="https://github.com/projectcalico/calico@v3.31.4"

# Just repo URL (ref taken from image tag)
--go-vcs-url="https://github.com/projectcalico/calico"
```

## Quick Start

```bash
# Scan the image
trivy image --vuln-type library --ignore-unfixed myimage:v1.0 -f json -o scan.json

# Patch with Go rebuild (auto-detection)
COPA_EXPERIMENTAL=1 copa patch \
  -i myimage:v1.0 \
  -r scan.json \
  -t myimage-patched \
  --pkg-types library \
  --ignore-errors

# Patch with explicit VCS override (for stripped binaries)
COPA_EXPERIMENTAL=1 copa patch \
  -i calico/cni:v3.31.4 \
  -r scan.json \
  -t calico-cni-patched \
  --pkg-types library \
  --go-vcs-url="https://github.com/projectcalico/calico@v3.31.4" \
  --ignore-errors
```

## Limitations

### CGO Binaries

Binaries built with `CGO_ENABLED=1` are **skipped** in v1. Rebuilding CGO binaries requires matching C libraries and toolchains, which is not yet supported.

Affected images: InfluxDB, SPIRE agent/server.

### Go Stdlib Vulnerabilities

Vulnerabilities in the Go standard library (reported as `stdlib` by Trivy) require upgrading the Go compiler itself. Copa logs a warning but does not attempt automatic compiler upgrades.

### VCS Info Requirements

The binary rebuild approach requires knowing where the source code lives. Without VCS info embedded AND without `--go-vcs-url`, Copa falls back to the tag heuristic. If that also fails, the binary is skipped with a warning.

Common reasons VCS info is missing:
- `.git` directory excluded from Docker build context
- Built with `-buildvcs=false`
- Built via `go build file.go` instead of module-aware build

### Private Repositories

Source repos must be accessible for cloning. Private repos require appropriate Git credentials to be configured in the build environment.

### Build Reproducibility

Rebuilt binaries will have different hashes than originals. This is expected — the binary contains updated dependency code. Existing image signatures or attestations will not validate against the rebuilt image.
