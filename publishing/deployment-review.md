# Deployment review — 2026-11-02

## Observed configuration

- GitHub Pages API: `build_type: legacy`, `source.branch: gh-pages`,
  `source.path: /`, custom domain `docs.jasonachkardiab.com`.
- `.github/workflows/content-quality.yml` runs quality, secret scanning and a
  canonical MkDocs build. PR runs produce artifacts without publication.
- `deploy-docs` runs only on a push to `main`, depends on all three checks, and
  downloads `verified-docs-${github.sha}`. It does not rebuild at publication.
- `scripts/publish-gh-pages.sh` replaces the isolated publication checkout with
  that artifact and commits only generated files to `gh-pages`.
- `docs-pipeline.json` and the MkDocs hook map canonical Markdown into the site;
  `publishing/content-status.json` governs route lifecycle and indexability.

These are T1 configuration observations, not evidence of a successful deployment
of the changes in this branch. The read-only Pages settings check was:

```sh
gh api repos/jasonachkar/cybersecurity-writeups/pages
```

## Change routing

| Change | Destination |
| --- | --- |
| Research, methodology, labs, tests, navigation, build inputs | `research-depth-upgrade` → PR into `main` |
| Rendered HTML, search index, sitemap, copied assets, manifest and CNAME | CI-generated `gh-pages` commit after merge |
| Cloud resources | No deployment authorized or performed by this work |

Preserve existing URLs, lifecycle records, custom domain, search and sitemap.
Mount new source roots through both the canonical inventory and MkDocs hook.
Check the built routes and local HTML links before proposing a merge.

## References

- [Publication workflow](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/.github/workflows/content-quality.yml)
- [Publication script](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/scripts/publish-gh-pages.sh)
- [Pipeline contract](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs-pipeline.json)
