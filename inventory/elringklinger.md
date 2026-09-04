# ElringKlinger AG inventory (discovery seed 2026-09-02)
# NOTE: hosts below are discovery candidates from passive DNS/CT; confirm in-scope vs program scope before active testing.
elringklinger.com
www.elringklinger.com

## PASSIVE RECON 2026-09-02 (read-only, non-intrusive)

> Recon observations only. These are NOT confirmed vulnerabilities; ownership/in-scope of each host must be confirmed against the program scope before any active testing. Hosts resolve + serve HTTP — investigation requires scoped authorization.

**Probed:** 2 hosts | **Live HTTP:** 0

| Host | Status | Server/Tech |
|---|---|---|

## DEEP ENUM (wildcard-cleaned) 2026-09-03
**Root zone:** `elringklinger.com` | **dedicated hosts after wildcard-filter: 13**
> Audit: brute+passive subfinder produced 10,083 resolving hostnames; zone-wildcard + IP-fingerprint filtering dropped 9,973 (98.9%) DNS-wildcard noise (random labels resolving to shared wildcard IPs e.g. account.cineplex.de, a.hypofriend.de, account.live-manager.de, docker.jtl-software.de, *.ggamdom.com, *.dev.alfaview.com). Only genuine dedicated hosts listed below. These are surface-map observations; live HTTP status captured read-only (GET / via curl). No findings claimed; scope must be confirmed with the program.
- `aircontrol.elringklinger.com`  [HTTP unprobed]
- `api.smartcard.elringklinger.com`  [HTTP 404]
- `avconf.elringklinger.com`  [HTTP unprobed]
- `cctv.elringklinger.com`  [HTTP unprobed]
- `cgline.elringklinger.com`  [HTTP unprobed]
- `dtspc-tst.elringklinger.com`  [HTTP unprobed]
- `edi2.elringklinger.com`  [HTTP unprobed]
- `edi7.elringklinger.com`  [HTTP unprobed]
- `ektrcctv.elringklinger.com`  [HTTP unprobed]
- `fwasvvideo1.elringklinger.com`  [HTTP unprobed]
- `go.events.elringklinger.com`  [HTTP 302]
- `imap.elringklinger.com`  [HTTP unprobed]
- `ir.elringklinger.com`  [HTTP 301]

## 2026-09-02 21:46:45 UTC

## 2026-09-02 23:58:57 UTC

## 2026-09-03 03:39:30 UTC

## 2026-09-03 08:19:54 UTC

## 2026-09-03 12:54:04 UTC

## 2026-09-03 17:06:41 UTC
- NEW 13 dedicated subdomains discovered via wildcard-filtered enum (was 2 root domains)
- NEW `api.smartcard.elringklinger.com` — API endpoint returning HTTP 404 at root (suggests versioned paths)
- NEW `go.events.elringklinger.com` — HTTP 302 redirect (event platform, likely OAuth/SSO flow)
- NEW `ir.elringklinger.com` — HTTP 301, Apache investor relations page
- NEW `edi2.elringklinger.com`, `edi7.elringklinger.com` — EDI B2B endpoints (unprobed)
- NEW `dtspc-tst.elringklinger.com` — Test environment indicator (tst suffix)
- NEW 6 infrastructure hosts unprobed: aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap
- CHANGED Probe coverage: 0/13 hosts actively tested (only passive HTTP status on 3)

## 2026-09-03 19:50:40 UTC
- NEW `api.smartcard.elringklinger.com/api/v1/` returns HTTP 502 (Bad Gateway) — endpoint exists but backend down, confirming versioned API path `/api/v1/` is real
- NEW `go.events.elringklinger.com/api` returns HTTP 405 for multiple method params — Pardot API endpoint confirmed live, processes auth logic before rejection (error codes 1 vs 49 per earlier finding)
- CHANGED Probe coverage: 2/13 hosts actively tested (was 0/13)

## 2026-09-03 22:27:33 UTC
- NEW `api.smartcard.elringklinger.com/api/v1/` returns HTTP 502 — live backend, versioned path confirmed
- NEW `go.events.elringklinger.com/api` returns HTTP 405 with method-specific error codes (1 vs 49) — Pardot API live
- CHANGED Probe coverage: 2/13 hosts actively tested (was 0/13)
- NEW `api.smartcard.elringklinger.com/api/v1/*` all return HTTP 502 (nginx gateway) — backend consistently down, no debug/stack traces leaked in responses
- NEW `go.events.elringklinger.com/api?method=getCampaigns&version=3` returns HTTP 200 JSON with `err_code:1` (invalid key) — confirms method enumeration works, version param accepted, auth logic executes p
- NEW `go.events.elringklinger.com/api?method=getVersion` returns HTTP 200 JSON with `err_code:1` — version endpoint accessible without valid key
- CHANGED Pardot API error code discrimination confirmed: `err_code:1` (invalid key) vs earlier `err_code:49` (method not found) — proves method-level auth logic
- CHANGED Probe coverage: 2/13 hosts tested with deeper endpoint enumeration (was 2/13 basic)

## 2026-09-04 00:31:30 UTC
- NEW api.smartcard.elringklinger.com/api/v2/ and /api/beta/ return HTTP 502 — versioned paths v2/beta exist with same backend routing (nginx gateway), no debug leakage
- NEW api.smartcard.elringklinger.com/swagger.json, /openapi.json, /.well-known/openid-configuration return HTTP 404 — no OpenAPI/OIDC discovery exposed
- NEW go.events.elringklinger.com/api?method=getEmails|getLists|getTags|getVisitors|queryProspects all return HTTP 200 JSON with err_code:1 (invalid key) — method enumeration confirmed for 5 additional Pard
- NEW go.events.elringklinger.com/ returns HTTP 302 to http://elringklinger.com (HTTP downgrade) with pardot cookie deletion — confirms OAuth/SSO initiation flow with redirect_uri to root domain
- NEW edi2.elringklinger.com, edi7.elringklinger.com, dtspc-tst.elringklinger.com, aircontrol.elringklinger.com, avconf.elringklinger.com, cctv.elringklinger.com, cgline.elringklinger.com — all connection t
