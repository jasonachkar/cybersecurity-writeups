# Content metadata contract

Indexed security articles use YAML front matter so currency, evidence quality, and
implementation status can be checked mechanically. Metadata supports review; it is
not a substitute for technical verification.

## Required fields

```yaml
---
title: "Precise article title"
id: "stable-kebab-case-id"
navTitle: "Concise navigation title"
order: 10
type: "cloud-security"
tags:
  - identity
date: "2026-07-21"
lastReviewed: "2026-07-21"
reviewStatus: "requires-review"
validatedAgainst:
  - "AWS IAM documentation checked 2026-07-21"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 180
---
```

| Field | Rules |
| --- | --- |
| `title` | Unique, nonempty string. |
| `id` | Stable, globally unique lowercase kebab-case ID for a primary research article. Do not change it when a title changes. |
| `navTitle` | Concise label used in navigation and relationship cards. |
| `order` | Positive integer controlling the article's order inside its domain. Use gaps of 10. |
| `type` | `cloud-security`, `appsec`, `devsecops`, `threat-intel`, `tutorial`, `research`, or `certification-notes`. |
| `tags` | Nonempty list of lowercase topics. |
| `date` | Original publication or substantial-rewrite date, `YYYY-MM-DD`. |
| `lastReviewed` | Date evidence and examples were last evaluated, `YYYY-MM-DD`. |
| `readingTime` | Optional positive-integer override. Normally omit it; the catalog derives minutes deterministically from prose at 225 words per minute and excludes fenced code. |
| `reviewStatus` | `verified`, `partially-verified`, `requires-review`, or `historical`. |
| `validatedAgainst` | Nonempty list for verified material; exact versions, standards, product documentation, or linked labs. |
| `sourceQuality` | `primary-sources-reviewed`, `mixed-sources`, or `requires-review`. |
| `implementationStatus` | `tested`, `partially-tested`, `illustrative`, or `pseudocode`. |
| `reviewIntervalDays` | Positive integer; normally 180 for fast-moving guidance or 365 for conceptual material. |

Primary research may also supply `summary`, `keyTakeaway`, `featured`,
`featuredOrder`, and typed `related` lists (`research`, `labs`, and `scripts`). A
featured article must have a reviewed summary and positive featured order. Related
values are stable IDs, not paths; the renderer adds the reciprocal relationship.
Unknown, duplicate, self-referential, archived, or wrong-type IDs fail validation.

Lab `README.md` frontmatter uses the same stable-ID model and additionally declares
`domain`, `summary`, `sourceFiles`, `runCommands`, and implementation status. Script
metadata lives only in `site-pages/scripts/catalog.yml`; source and test paths,
safety labels, ordering, and relations must not be duplicated in Markdown.

## Review semantics

- `verified` means every material current-state claim was checked against the listed
  evidence and important runnable examples are accurately labeled.
- `partially-verified` identifies a bounded, documented validation gap.
- `requires-review` is the safe migration state for legacy content. A fresh
  `lastReviewed` value does not promote it.
- `historical` is for intentionally preserved historical material, not an excuse for
  stale recommendations.

`validatedAgainst` records what was actually checked. It should not be a generic
standards wishlist. Put full links in the article's `References` section.

## CI behavior

`npm run metadata:check` and `npm run docs:catalog` reject missing or malformed required fields, duplicate
titles, impossible future review dates, and unsupported status values. The freshness
check reports pages whose review interval has elapsed. The structural check verifies
that substantive material exposes evidence and that flagship articles include
engineering, operational, and validation sections.
