# Trust Breaker

Trust Breaker extracts package URLs from an SBOM and retrieves vulnerability data from multiple sources for comparison:

1. **[OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)** — batched advisory lookups resolved to CVE-level records.
2. **RHTPA** (optional) — Red Hat Trusted Profile Analyzer vulnerability API.
3. **Exhort** (optional) — Exhort vulnerability analysis API.

After retrieval, sources are compared and gaps are identified. An optional **categorize** step classifies TPA gaps using OSV advisory scope checks, CSAF cross-verification, and CVE status validation.

## Pre-Requisites

- [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html)
- `rpmdev-vercmp` (from `rpmdevtools`) — required only when `--categorize` is used

## Installation

```sh
git clone https://github.com/mrrajan/trust_breaker.git
cd trust_breaker
cargo build
```

## Usage

### OSV querybatch only (from SBOM)

```sh
cargo run -- -s /path/to/your/sbom.json -t cdx
# or SPDX:
cargo run -- -s /path/to/your/sbom.json -t spdx
```

### From a pre-extracted PURLs file

```sh
cargo run -- -p /path/to/purls.txt -t spdx
```

### OSV + RHTPA + Exhort

```sh
cargo run -- \
  -s /path/to/your/sbom.json \
  -t cdx \
  -r <RHTPA_BASE_URL> \
  -a <RHTPA_ACCESS_TOKEN> \
  -e <EXHORT_API_URL>
```

### With TPA gap categorization

```sh
cargo run -- \
  -s /path/to/your/sbom.json \
  -t spdx \
  -r <RHTPA_BASE_URL> \
  --categorize
```

## Arguments

| Flag | Long | Description |
|------|------|-------------|
| `-s` | `--sbom_file` | Path to SBOM file (CycloneDX or SPDX JSON) |
| `-t` | `--sbom_type` | SBOM type: `cdx` or `spdx` (required) |
| `-p` | `--purls_file` | Pre-extracted PURLs text file (skips SBOM extraction) |
| `-r` | `--tpa_url` | RHTPA base URL |
| `-a` | `--tpa_token` | RHTPA access token |
| `-e` | `--exhort_url` | Exhort API URL |
| `-c` | `--categorize` | Categorize TPA gaps after comparison (requires `rpmdev-vercmp`) |

Either `-s` or `-p` is required. Omit `-a` to call RHTPA without a bearer token.

## Outputs

Files are written under `test_results/`:

| File | Description |
|------|-------------|
| `exhort_validator.log` | Run log |
| `source/{type}_purls_{ts}.json` | PURLs extracted from SBOM |
| `source/{type}_purls_{ts}.txt` | Same PURLs, one per line |
| `source/{type}_osv_querybatch_{ts}.json` | OSV querybatch results keyed by PURL |
| `source/{type}_osv_querybatch_{ts}.csv` | Flattened PURL, OSV_ID, MODIFIED rows |
| `source/{type}_osv_cves_{ts}.csv` | OSV advisory-to-CVE resolved records |
| `source/tpa_response_{ts}.csv` | RHTPA flattened rows |
| `source/exhort_response_{ts}.csv` | Exhort flattened rows |
| `comparison/comparison_osv_vs_tpa.csv` | OSV vs TPA diff |
| `comparison/comparison_tpa_vs_exhort.csv` | TPA vs Exhort diff |

### Categorize columns (when `--categorize` is used)

The comparison CSV is enriched with:

| Column | Values |
|--------|--------|
| `finding` | `TPA_MISS`, `VERSION_NOT_AFFECTED`, `ECOSYSTEM_MISMATCH`, `CROSS_PACKAGE`, `CVE_WITHDRAWN`, `UNKNOWN` |
| `verdict` | `TPA_GAP` (genuine miss) or `OSV_NOISE` (false positive) |
| `matched_advisory` | The Red Hat advisory ID used for classification |
