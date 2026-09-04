# Validated findings (running count 0)

- 9 lead(s) marked VALID at 2026-09-03 19:42:50 UTC
  - | Q1 Scope | **VALID** — `*.elringklinger.com` is in-scope per scope.yml (all company-owned infrastructure) |
  - | Q2 Reachable | **VALID** — Public endpoint, no auth required to probe |
  - | Q6 Not always-rejected | **VALID** — Not on out-of-scope list |
  - | Q1 Scope | **VALID** — `*.elringklinger.com` is in-scope |
  - | Q2 Reachable | **VALID** — Public, unauthenticated |
  - | Q6 Not always-rejected | **VALID** |
  - | Q1 Scope | **VALID** |
  - | Q2 Reachable | **VALID** |
  - | Q6 Not always-rejected | **VALID** |

- 2 lead(s) marked VALID at 2026-09-04 22:14:14 UTC
  - | Q3 | Real security impact? | **No.** All methods require valid API key. Error-code discrimination (1 vs 49) proves auth logic executes pre-rejection — this is normal Pardot behavior, not a flaw. No 
  - | 1 | Pardot v5 Bearer Auth Bypass | **HOLD** | Confirmed real flaw (85-90 confidence), but v5 tier now returns 198 — appears disabled. Hold 24-48h to confirm. If tier reappears → VALID. If stays down
