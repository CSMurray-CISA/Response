# Unified Vulnerability Platform

This GitHub Pages site combines four tools behind one Advisory Lens–styled switcher. A shared `platform-theme.css` gives the Vulnerability Dashboard, SSVC Scoring, and KEV with SSVC the same dark green palette, typography, controls, panels, tables, and responsive treatment as Advisory Lens while leaving their underlying workflows intact.

1. **Advisory Analysis** — the current `CSMurray-CISA/AdvisoryAnalysis` site, unchanged.
2. **Vulnerability Dashboard** — the original standalone `CSMurray1/VulnDashboard` `index.html`, unchanged.
3. **SSVC Scoring** — the multi-vendor SSVC dashboard from `CSMurray-CISA/ssvc`.
4. **KEV with SSVC** — a filterable, staged view of the complete CISA KEV catalog enriched with CISA Vulnrichment SSVC, CVSS, and CWE data.

Each tool runs in its own same-site frame. This keeps its HTML, styles, scripts, state, file uploads, filters, and exports isolated from the other tools. The Vulnerability Dashboard therefore retains the behavior of the original standalone version instead of the altered version from the combined SSVC repository.

## Publish with GitHub Pages

Copy the complete contents of this folder into the root of the GitHub repository you want to publish. Keep all folders, including `.github`, `oracle-data`, and `vendor-data`.

Then open **Settings → Pages**, choose **Deploy from a branch**, select the branch and the root (`/`) folder, and save. There is no website build step.

The site opens to Advisory Analysis. The floating switcher changes between tools without resetting work already performed in another tool. Each tool also has a direct URL:

- `advisory-analysis.html`
- `vulnerability-dashboard.html`
- `ssvc-dashboard.html`
- `kev-ssvc.html`

## SSVC vendor-data refresh

The included GitHub Actions workflow retains the SSVC repository's daily vendor-data refresh. After copying the site to a new repository, open **Actions → Refresh CISA SSVC Platform vendor data → Run workflow** once to confirm that Actions have write permission and the parsers can refresh the tracked data.

The entire `oracle-data/` and `vendor-data/` directories must remain in the repository. The SSVC dashboard reads those JSON files directly from GitHub Pages.

## KEV with SSVC refresh

The **Refresh KEV with SSVC data** workflow runs hourly and can also be started manually. It downloads the current KEV catalog from `cisagov/kev-data`, checks out only the matching CVE records from `cisagov/vulnrichment`, merges the data into `data/kev-ssvc.json`, runs the test suite, and commits only when the staged dataset changes.

The page reads only this same-site staged JSON file. It makes no live browser requests to CISA.gov, CVE.org, NVD, or GitHub. The initial staged dataset is already included, so the page works before the first Action run.

## Source mapping

- `index.html`: new unified platform switcher
- `advisory-analysis.html`, `app.js`, `styles.css`: AdvisoryAnalysis
- `vulnerability-dashboard.html`: original VulnDashboard standalone page
- `ssvc-dashboard.html`, `oracle-data/`, `vendor-data/`: SSVC dashboard and tracked data
- `platform-theme.css`: shared Advisory Lens visual theme for VulnDashboard and SSVC
- `kev-ssvc.html`, `kev-ssvc.css`, `kev-ssvc.js`: filterable KEV and SSVC interface
- `data/kev-ssvc.json`: staged KEV/Vulnrichment dataset used by the fourth page
- `scripts/build_kev_ssvc.py`: deterministic KEV and Vulnrichment merge tool
- `.github/workflows/refresh-kev-ssvc.yml`: hourly staged-data refresh
- `scripts/`, `requirements.txt`, `.github/workflows/`: SSVC data-refresh automation
