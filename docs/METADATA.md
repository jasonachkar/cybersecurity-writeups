# Content metadata contract

Indexed security articles use YAML front matter so currency, evidence quality, and
implementation status can be checked mechanically. Metadata supports review; it is
not a substitute for technical verification.

## Required fields

```yaml
---
title: "Precise article title"
type: "cloud-security"
tags:
  - identity
date: "2026-07-21"
lastReviewed: "2026-07-21"
readingTime: 20
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
| `type` | `cloud-security`, `appsec`, `devsecops`, `threat-intel`, `tutorial`, `research`, or `certification-notes`. |
| `tags` | Nonempty list of lowercase topics. |
| `date` | Original publication or substantial-rewrite date, `YYYY-MM-DD`. |
| `lastReviewed` | Date evidence and examples were last evaluated, `YYYY-MM-DD`. |
| `readingTime` | Estimated minutes as a positive integer. |
| `reviewStatus` | `verified`, `partially-verified`, `requires-review`, or `historical`. |
| `validatedAgainst` | Nonempty list for verified material; exact versions, standards, product documentation, or linked labs. |
| `sourceQuality` | `primary-sources-reviewed`, `mixed-sources`, or `requires-review`. |
| `implementationStatus` | `tested`, `partially-tested`, `illustrative`, or `pseudocode`. |
| `reviewIntervalDays` | Positive integer; normally 180 for fast-moving guidance or 365 for conceptual material. |

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

`npm run metadata:check` rejects missing or malformed required fields, duplicate
titles, impossible future review dates, and unsupported status values. The freshness
check reports pages whose review interval has elapsed. The structural check verifies
that substantive material exposes evidence and that flagship articles include
engineering, operational, and validation sections.
