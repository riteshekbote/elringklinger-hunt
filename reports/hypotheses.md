# Hypotheses (ranked)

## RANKED HYPOTHESES 2026-09-02 21:46:45 UTC

## RANKED HYPOTHESES 2026-09-02 23:58:57 UTC

## RANKED HYPOTHESES 2026-09-03 03:39:30 UTC

## RANKED HYPOTHESES 2026-09-03 08:19:54 UTC

## RANKED HYPOTHESES 2026-09-03 12:54:04 UTC

## RANKED HYPOTHESES 2026-09-03 17:06:41 UTC
- [70] api.smartcard.elringklinger.com: Smartcard API — Broken Auth/IDOR on Versioned Endpoints (from art/lead_nemotron3.txt)
- [65] go.events.elringklinger.com: Pardot API version/format enumeration + info disclosure (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://api.smartcard.elringklinger.com/api/v1/ && GET https://api.smartcard.elringklinger.com/v2/ && GET https://api.smartcard.elringklinger.com/swa
- NEXT(hypotheses-bigpickle.txt): PROBE: Test Pardot API method enumeration to discover accessible endpoints — exact request: `curl -sS --max-time 8 "https://go.events.elringklinger.com/api?api_
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: 404 at root on API-named host strongly indicates versioned endpoints; auth systems are high-value per directive
- LEARN: ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws are chainable to ATO
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints are documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error code discrimination (1 vs 49) confirms API processes auth logic before rejection. Method enume
- LEARN: REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
- LEARN: ACCEPTED MISCONFIG @ go.events.elringklinger.com: HTTP downgrade redirect is real but low-severity. Worth tracking as chain primitive (e.g. combined with phishi

## RANKED HYPOTHESES 2026-09-03 19:50:40 UTC
- [80] api.smartcard.elringklinger.com: Smartcard API — Broken Auth/IDOR on Versioned /api/v1/ Endpoint (Backend Down) (from art/lead_nemotron3.txt)
- [72] api.smartcard.elringklinger.com: Smartcard API versioned endpoint enumeration via path traversal (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: Test Smartcard API versioned endpoints with exact requests:
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://api.smartcard.elringklinger.com/api/v1/ (capture full response body/headers) && GET https://api.smartcard.elringklinger.com/api/v1/health && 
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Versioned endpoints likely exist based on 404 at root. Auth systems are high-value targets per directives.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error discrimination confirms method-level authorization logic. Enumeration may reveal accessible en
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange fits program scope.
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives.
- LEARN: REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/ returns 502 confirming versioned endpoint exists with live backend routing — auth systems high-value p
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api returns 405 with method-specific error codes (1 vs 49) proving auth logic executes pre-rejection; m
- LEARN: ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws chainable to ATO
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-03 22:27:33 UTC
- [72] api.smartcard.elringklinger.com: Smartcard API versioned endpoint enumeration via path traversal (from art/lead_bigpickle.txt)
- [65] api.smartcard.elringklinger.com: Smartcard API — Versioned Endpoint Enumeration + Backend Downtime Info Leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: Test Smartcard API versioned endpoints with exact requests:
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://api.smartcard.elringklinger.com/api/v2/ && GET https://api.smartcard.elringklinger.com/api/beta/ && GET https://api.smartcard.elringklinger.c
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Versioned endpoints likely exist based on 404 at root. Auth systems are high-value targets per directives.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error discrimination confirms method-level authorization logic. Enumeration may reveal accessible en
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange fits program scope.
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives.
- LEARN: REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/* returns 502 confirming versioned endpoint exists with live backend routing — auth systems high-value 
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api returns 200 JSON with err_code discrimination (1 vs 49) proving auth logic executes pre-rejection; 
- LEARN: ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws chainable to ATO
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 00:31:30 UTC
- [75] go.events.elringklinger.com: Events Platform — Pardot OAuth/SSO redirect_uri Validation Flaw (from art/lead_nemotron3.txt)
- [48] api.smartcard.elringklinger.com: Smartcard API backend-downtime information disclosure via gateway headers (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/login?redirect_uri=https://evil.com && GET https://go.events.elringklinger.com/auth?redirect_uri=https://evil.com
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/ return 502 confirming versioned endpoint routing exists with live nginx gateway 
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api method enumeration confirmed for getCampaigns, getVersion, getEmails, getLists, getTags, getVisitor
- LEARN: ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect to http://elringklinger.com (HTTP downgrade) with pardot cookie deletion — classic OAuth/SSO initiatio
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unr
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 05:15:50 UTC
- [80] go.events.elringklinger.com: Events Platform — Pardot API Unauthenticated Method Enumeration + Version Parameter Access (from art/lead_nemotron3.txt)
- [42] go.events.elringklinger.com/api/v5: Pardot v5 API tier exposes distinct auth-gated endpoints with different key/credential requirements (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=2 && GET https://go.events.elringklinger.com/api?api_key=t
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://go.events.elringklinger.com/api/v5/campaign, GET https://go.events.elringklinger.com/api/v5/prospect, GET https://go.events.elringklinger.com
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api method enumeration confirmed for 7 methods (getCampaigns, getVersion, getEmails, getLists, getTags,
- LEARN: REJECTED OATH @ go.events.elringklinger.com: OAuth redirect_uri parameter tested on login, auth, oauth/authorize, oauth/token — all ignore parameter, redirect f
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/ return 502 confirming versioned endpoint routing exists with live nginx gateway 
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unr
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 09:47:59 UTC
- [70] go.events.elringklinger.com: Events Platform — Pardot API v5 REST Tier Enumeration + Auth Boundary Testing (from art/lead_nemotron3.txt)
- [45] api.smartcard.elringklinger.com: Smartcard API backend recovery probe across versioned paths (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: Re-check Smartcard backend + probe Pardot v5 resources + try dtspc-tst. Three parallel GETs:
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api/v5/campaign && GET https://go.events.elringklinger.com/api/v5/prospect && GET https://go.events.elringklinger
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend 502 for 30+ hours — transient outage, not architectural block. Recovery probe is passive and HIGH-value
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: v5 tier has distinct auth behavior (401 vs JSON err_code on v1-v4). Untested resource paths remain.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: 7 Pardot methods confirmed enumerable but all require valid API key (err_code:1). No unauthenticated data path 
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api method enumeration confirmed for 7 methods (getCampaigns, getVersion, getEmails, getLists, getTags,
- LEARN: REJECTED OATH @ go.events.elringklinger.com: OAuth redirect_uri parameter tested on login, auth, oauth/authorize, oauth/token — all ignore parameter, redirect f
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/ return 502 confirming versioned endpoint routing exists with live nginx gateway 
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unr
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 14:13:20 UTC
- [85] go.events.elringklinger.com/api/v5: Pardot v5 API Complete Bearer Authentication Bypass — 18 Resource Endpoints Unauthenticated (from art/lead_bigpickle.txt)
- [75] go.events.elringklinger.com: Events Platform — Pardot API v5 REST Tier Auth Boundary + Resource Enumeration (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): RAG: Search Google/GitHub/cert transparency for ElringKlinger Pardot Business Unit ID (format: 0Uv + 15 Salesforce base62 chars). Check elring.com, elring.de, e
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api/v5/emails && GET https://go.events.elringklinger.com/api/v5/lists && GET https://go.events.elringklinger.com/
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: Complete Bearer auth bypass — any string accepted as Authorization token. 18 object endpoints live. Only bar
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api/v5: Error code catalog mapped: 49=Access Denied (no auth), 181=Missing BU header, 182=Invalid BU format (exp
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: 18 REST resource endpoints confirmed live on v5 tier: prospects, campaigns, visitors, users, lists, folders,
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — not firewalled, simply not responding. Dead host.
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours. No recovery.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api/v5/* endpoints exist and return 401 JSON `{"code":49,"message":"Access Denied"}` — distinct REST ti
- LEARN: REJECTED OATH @ go.events.elringklinger.com: OAuth redirect_uri parameter tested on 4 endpoints — all ignore parameter, redirect fixed to http://elringklinger.c
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/, /api/v1/auth, /api/v1/tokens, /api/v1/cards, /api/v1/health all return 502 — ve
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unr
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 17:48:30 UTC
- [85] go.events.elringklinger.com/api/v5: Pardot v5 API Complete Bearer Authentication Bypass — 18 Resource Endpoints Unauthenticated (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): RAG: Search Google/GitHub/cert transparency for ElringKlinger Pardot Business Unit ID (format: 0Uv + 15 Salesforce base62 chars). Check elring.com, elring.de, e
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: Complete Bearer auth bypass — any string accepted as Authorization token. 18 object endpoints live. Only bar
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api/v5: Error code catalog mapped: 49=Access Denied (no auth), 181=Missing BU header, 182=Invalid BU format (exp
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: 18 REST resource endpoints confirmed live on v5 tier: prospects, campaigns, visitors, users, lists, folders,
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — not firewalled, simply not responding. Dead host.
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours. No recovery.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api/v5/* endpoints exist and return 401 JSON `{"code":49,"message":"Access Denied"}` — distinct REST ti
- LEARN: REJECTED OATH @ go.events.elringklinger.com: OAuth redirect_uri parameter tested on 4 endpoints — all ignore parameter, redirect fixed to http://elringklinger.c
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/, /api/v1/auth, /api/v1/tokens, /api/v1/cards, /api/v1/health all return 502 — ve
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unr
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives

## RANKED HYPOTHESES 2026-09-04 20:06:39 UTC
- [70] go.events.elringklinger.com/api: Pardot Legacy API Method Enumeration — Auth Logic Bypass via Error Discrimination (from art/lead_nemotron3.txt)
- [70] api.smartcard.elringklinger.com: Smartcard API — Broken Auth/IDOR on Versioned Endpoints (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://api.smartcard.elringklinger.com/api/v1/ && GET https://api.smartcard.elringklinger.com/v2/ && GET https://api.smartcard.elringklinger.com/swa
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api?method=getVersion&version=3 && GET https://go.events.elringklinger.com/api?method=getCampaigns&version=3 && G
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: 404 at root on API-named host strongly indicates versioned endpoints; auth systems are high-value per directive
- LEARN: ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws are chainable to ATO
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints are documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: v5 tier has distinct auth behavior (401 vs JSON err_code on v1-v4). Untested resource paths remain.
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com: 7 Pardot methods confirmed enumerable but all require valid API key (err_code:1). No unauthenticated data path 
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: Complete Bearer auth bypass — any string accepted as Authorization token. 18 object endpoints live. Only bar
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api/v5: Error code catalog mapped: 49=Access Denied (no auth), 181=Missing BU header, 182=Invalid BU format (exp
- LEARN: ACCEPTED AUTH @ go.events.elringklinger.com/api/v5: 18 REST resource endpoints confirmed live on v5 tier: prospects, campaigns, visitors, users, lists, folders,
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — not firewalled, simply not responding. Dead host.
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours. No recovery.
- LEARN: REJECTED AUTH @ go.events.elringklinger.com/api/v5: v5 REST tier (18 endpoints) now returns 198 "Endpoint not found" — tier disabled/removed, Bearer bypass no l
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api: Legacy Pardot /api?method= endpoint returns 200 JSON with err_code:49 (Access Denied) for 7 methods — auth 
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours across all versioned paths — transient outage, nginx gateway live
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — dead host
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots — but hosts unreachable (timeout)
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface

## RANKED HYPOTHESES 2026-09-04 22:16:28 UTC
- [70] go.events.elringklinger.com/api: Pardot Legacy API Method Enumeration — Auth Logic Bypass via Error Discrimination (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: `GET https://api.smartcard.elringklinger.com/api/v1/` (1rps read-only) — backend-recovery check, only remaining path to a HIGH-severity finding; run alon
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api?method=getVersion&version=3 && GET https://go.events.elringklinger.com/api?method=getCampaigns&version=3 && G
- LEARN: REJECTED AUTH @ go.events.elringklinger.com/api/v5: v5 REST tier (18 endpoints) now returns 198 "Endpoint not found" — tier disabled/removed, Bearer bypass no l
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api: Legacy Pardot /api?method= endpoint returns 200 JSON with err_code:49 (Access Denied) for 7 methods — auth 
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours across all versioned paths — transient outage, nginx gateway live
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — dead host
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots — but hosts unreachable (timeout)
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface

## RANKED HYPOTHESES 2026-09-05 00:13:47 UTC
- [85] go.events.elringklinger.com/api/v5/*: Pardot v5 API — Missing Bearer-Token Validation (auth skipped at token layer; dormant tier) (from art/lead_bigpickle.txt)
- [70] go.events.elringklinger.com/api: Pardot Legacy API Method Enumeration — Auth Logic Bypass via Error Discrimination (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: `GET https://go.events.elringklinger.com/api?method=getVersion&version=1` then `…&version=2` then `…&version=5` (1rps, passive) — determine if 401 enforc
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api?method=getVersion&version=3 && GET https://go.events.elringklinger.com/api?method=getCampaigns&version=3 && G
- LEARN: REJECTED AUTH @ go.events.elringklinger.com/api/v5: v5 REST tier (18 endpoints) now returns 198 "Endpoint not found" — tier disabled/removed, Bearer bypass no l
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api: Legacy Pardot /api?method= endpoint returns 200 JSON with err_code:49 (Access Denied) for 7 methods — auth 
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 30+ hours across all versioned paths — transient outage, nginx gateway live
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — dead host
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots — but hosts unreachable (timeout)
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface

## RANKED HYPOTHESES 2026-09-05 04:42:31 UTC
- [85] go.events.elringklinger.com/api/v5/*: Pardot v5 — Missing Bearer-Token Validation (dormant tier; highest-value archived finding) (from art/lead_bigpickle.txt)
- [70] go.events.elringklinger.com/api: Pardot Legacy API Method Enumeration — Auth Logic Bypass via Error Discrimination (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: `GET https://go.events.elringklinger.com/api/v5/prospects` with `Authorization: Bearer <garbage>` + `Pardot-Business-Unit-Id: 0Uv510000000000000` (1rps, 
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://go.events.elringklinger.com/api?method=getVersion&version=3 && GET https://go.events.elringklinger.com/api?method=getCampaigns&version=3 && G
- LEARN: REJECTED AUTH @ go.events.elringklinger.com/api/v5: v5 REST tier (18 endpoints) now returns 198 "Endpoint not found" — tier disabled/removed, Bearer bypass no l
- LEARN: ACCEPTED BUSLOGIC @ go.events.elringklinger.com/api: Legacy Pardot /api?method= endpoint returns 200 JSON with err_code:49 (Access Denied) for 7 methods — auth 
- LEARN: ACCEPTED AUTH @ api.smartcard.elringklinger.com: Backend still 502 after 32+ hours across all versioned paths — transient outage, nginx gateway live
- LEARN: REJECTED OTHER @ dtspc-tst.elringklinger.com: Host unreachable (000 timeout) — dead host
- LEARN: ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots — but hosts unreachable (timeout)
- LEARN: REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface
