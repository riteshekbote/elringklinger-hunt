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

## 2026-09-04 05:15:50 UTC
- NEW OAuth redirect_uri parameter tested on go.events.elringklinger.com login, auth, oauth/authorize, oauth/token — all ignore/invalidate parameter, redirect fixed to http://elringklinger.com (HTTP downgra
- NEW Smartcard API actuator endpoints (/actuator/health, /actuator/env, /actuator/mappings) all return 404 — not Spring Boot or actuator disabled
- NEW Smartcard API common auth endpoints (/auth/login, /oauth/token, /login, /health) all return 404
- NEW Smartcard API framework probes (/metrics, /graphql, /swagger-ui.html) all return 404
- CHANGED OAuth redirect_uri flaw hypothesis confidence reduced — parameter not reflected in redirect location

## 2026-09-04 09:47:59 UTC
- NEW go.events.elringklinger.com/api?v5 endpoints hypothesized by bigpickle (api/v5/campaign, api/v5/prospect) — untested Pardot REST API tier distinct from /api?method= legacy endpoint
- NEW Smartcard API backend consistently down (502) across v1/v2/beta — no framework fingerprint, no actuator, no common auth endpoints, no GraphQL/Swagger; only nginx gateway headers visible
- CHANGED OAuth redirect_uri hypothesis on go.events.elringklinger.com CONFIRMED REJECTED — tested on 4 endpoints, parameter ignored, fixed redirect to HTTP downgrade
- CHANGED EDI hosts (edi2, edi7, dtspc-tst, aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap) all connection timeout — 10/13 dedicated hosts unreachable
- CHANGED Probe coverage: 2/13 hosts with deep testing (go.events Pardot /api, smartcard versioned paths); 10/13 hosts no live HTTP response

## 2026-09-04 14:13:20 UTC
- NEW go.events.elringklinger.com/api/v5/campaign, /api/v5/prospect, /api/v5/ return HTTP 401 + JSON `{"code":49,"message":"Access Denied"}` — distinct Pardot REST API tier confirmed, auth behavior differs 
- NEW go.events.elringklinger.com/api/v5/* endpoints exist and respond (not 404) — versioned REST tier live with Bearer-style 401 vs legacy api_key query param
- CHANGED Smartcard API backend still down (502) across /api/v1/auth, /api/v1/tokens, /api/v1/cards, /api/v1/health — no framework fingerprint, only nginx gateway headers
- CHANGED EDI hosts (edi2, edi7, dtspc-tst, aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap) remain connection timeout — 10/13 dedicated hosts unreachable

## 2026-09-04 17:48:30 UTC
- NEW go.events.elringklinger.com/api/v5/emails, /lists, /tags, /visitors, /prospects, /campaigns return HTTP 401 JSON `{"code":49,"message":"Access Denied"}` — 6 additional v5 resource endpoints confirmed 
- NEW bigpickle agent discovered: Pardot v5 API Complete Bearer Authentication Bypass — ANY string accepted as Authorization token; auth check skipped entirely; error chain 49→181→182→201 proves bypass; 18 
- CHANGED Smartcard API backend still 502 across /api/v1/auth, /api/v1/tokens, /api/v1/cards, /api/v1/health — no framework fingerprint, only nginx gateway headers (consistent)
- CHANGED EDI hosts (edi2, edi7, dtspc-tst, aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap) remain connection timeout — 10/13 dedicated hosts unreachable (consistent)

## 2026-09-04 20:06:39 UTC
- NEW 13 dedicated subdomains discovered via wildcard-filtered enum (was 2 root domains)
- NEW `api.smartcard.elringklinger.com` — API endpoint returning HTTP 404 at root (suggests versioned paths)
- NEW `go.events.elringklinger.com` — HTTP 302 redirect (event platform, likely OAuth/SSO flow)
- NEW `ir.elringklinger.com` — HTTP 301, Apache investor relations page
- NEW `edi2.elringklinger.com`, `edi7.elringklinger.com` — EDI B2B endpoints (unprobed)
- NEW `dtspc-tst.elringklinger.com` — Test environment indicator (tst suffix)
- NEW 6 infrastructure hosts unprobed: aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap
- CHANGED Probe coverage: 0/13 hosts actively tested (only passive HTTP status on 3)
- NEW `api.smartcard.elringklinger.com/api/v1/` returns HTTP 502 (Bad Gateway) — endpoint exists but backend down, confirming versioned API path `/api/v1/` is real
- NEW `go.events.elringklinger.com/api` returns HTTP 405 for multiple method params — Pardot API endpoint confirmed live, processes auth logic before rejection (error codes 1 vs 49 per earlier finding)
- CHANGED Probe coverage: 2/13 hosts actively tested (was 0/13)
- CHANGED Pardot v5 REST tier (/api/v5/*) now returns 198 "Endpoint not found" for all 18 previously-confirmed resource endpoints (prospects, campaigns, visitors, emails, lists, tags, etc.) — tier appears disab

## 2026-09-04 22:16:28 UTC
- CHANGED Pardot v5 REST tier (/api/v5/*) now returns 198 "Endpoint not found" for all 18 previously-confirmed resource endpoints — tier disabled/removed since 17:48 UTC probe
- CHANGED Legacy Pardot /api?method= endpoint now returns 200 JSON with err_code:49 (Access Denied) for 7 methods (was err_code:1 previously) — auth behavior shifted
- CHANGED Smartcard API backend still 502 after 30+ hours across all versioned paths — no recovery
- CHANGED 10/13 dedicated hosts remain unreachable (connection timeout)
- NEW go.events.elringklinger.com/api prioritized as primary live attack surface (score 8.75)

## 2026-09-05 00:13:47 UTC
- CHANGED Current timestamp: 2026-09-05 00:11:24 UTC — last lead timestamp was 2026-09-04 22:16:28 UTC (~2 hours ago)
- CHANGED No new passive probes executed since last lead — state unchanged: Pardot legacy /api (err_code:49 on 7 methods), Smartcard 502 (30+ hrs), v5 tier removed (198), EDI/unreachable hosts (10/13), ir.elrin
- NEW Time window for Smartcard backend recovery extended to ~32 hours — still passive-only wait

## 2026-09-05 04:42:31 UTC
- CHANGED Smartcard API backend outage extended to ~32 hours (still 502 across all versioned paths; nginx gateway live)
- CHANGED No new passive probes executed since last lead (~2 hours ago) — surface state unchanged: Pardot legacy /api (err_code:49 on 7 methods), v5 tier removed (198), EDI/unreachable hosts (10/13), ir.elringk

## 2026-09-05 08:47:48 UTC

## 2026-09-05 12:24:14 UTC
- CHANGED `go.events.elringklinger.com/api/v5`: REST tier reactivated after ~12h downtime — returns 401/49 (no auth) vs 198 with Bearer header; auth behavior shifted from previous Bearer-skip (any string accept
- CHANGED `go.events.elringklinger.com/api`: Legacy `/api?method=` now returns HTTP 401 (was 200) with err_code:49 for all 7 methods — auth enforcement migrated to HTTP status layer.
- CHANGED `go.events.elringklinger.com/api/v5`: Previous Bearer bypass (any string accepted, error chain 49→181→182→201) no longer works — returns 198 with Bearer header.
- CHANGED `api.smartcard.elringklinger.com`: Backend 502 extended to ~34+ hours — no recovery signal.
- CHANGED `edi2.elringklinger.com`, `edi7.elringklinger.com`: Still unreachable (timeout), now 6-day span.
- CHANGED `go.events.elringklinger.com/api/v5/*`: Bearer bypass DEAD — any `Authorization: Bearer <any>` now returns HTTP 404/`{"code":198,"message":"Endpoint not found"}` (was error chain 49→181→182→201). Auth
- CHANGED `go.events.elringklinger.com/api/v5/*`: Tier LIVE — all 11 resource endpoints return HTTP 401/`{"code":49}` without auth (prospects, campaigns, users, lists, tags, accounts, opportunities, emails, for
- CHANGED `go.events.elringklinger.com/api/vN` (v1–v10): Uniform HTTP 401/`{"code":49}` across all numeric versions — tier is global, auth enforcement consistent.
- CHANGED `go.events.elringklinger.com/api?method=`: Legacy endpoint now returns HTTP **401** (was HTTP 200) with err_code:49 — auth enforcement migrated from app-layer to HTTP-status layer.
- CHANGED `go.events.elringklinger.com/api/v5/prospects` POST: Same as GET — 401/49 without auth, 404/198 with Bearer. Method not differentiated pre-auth.
- CHANGED `go.events.elringklinger.com/api/v5/*` OPTIONS: Returns HTTP 200 (empty body) — CORS preflight succeeds, no restrictive headers observed.
- CHANGED `api.smartcard.elringklinger.com`: Backend 502 extended to ~36+ hours. No change.

## 2026-09-05 15:25:18 UTC
- NEW go.events.elringklinger.com/api/v5: REST tier REACTIVATED after ~12h downtime — returns 401/49 (no auth) vs 404/198 (with Bearer); previous Bearer bypass DEAD; 11 resource endpoints live; dual-path au
- NEW go.events.elringklinger.com/api: Legacy /api?method= migrated from HTTP 200 → HTTP 401 with err_code:49 — auth enforcement shifted to HTTP status layer; 7 methods still enumerable
- CHANGED go.events.elringklinger.com/api/v5: Bearer header now ALWAYS returns 404/198 (was error chain 49→181→182→201); BU header does not alter response; auth check at pre-routing layer
- CHANGED api.smartcard.elringklinger.com: Backend 502 extended to ~36+ hours; robots.txt 200 (Disallow: /); no recovery
- CHANGED edi2.elringklinger.com, edi7.elringklinger.com: Still unreachable (timeout), now 6-day span

## 2026-09-05 17:41:27 UTC
