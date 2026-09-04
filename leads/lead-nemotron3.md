## 2026-09-03 17:06:29 UTC [target] (model nemotron3)
[NEW] 13 dedicated subdomains discovered via wildcard-filtered enum (was 2 root domains)
[NEW] `api.smartcard.elringklinger.com` — API endpoint returning HTTP 404 at root (suggests versioned paths)
[NEW] `go.events.elringklinger.com` — HTTP 302 redirect (event platform, likely OAuth/SSO flow)
[NEW] `ir.elringklinger.com` — HTTP 301, Apache investor relations page
[NEW] `edi2.elringklinger.com`, `edi7.elringklinger.com` — EDI B2B endpoints (unprobed)
[NEW] `dtspc-tst.elringklinger.com` — Test environment indicator (tst suffix)
[NEW] 6 infrastructure hosts unprobed: aircontrol, avconf, cctv, cgline, ektrcctv, fwasvvideo1, imap
[CHANGED] Probe coverage: 0/13 hosts actively tested (only passive HTTP status on 3)
[PRIO] api.smartcard.elringklinger.com,8.25,attack_surface=9,business_value=9,tech_exposure=8,gate_ease=7,cloud_surface=7,freshness=8
[PRIO] go.events.elringklinger.com,7.90,attack_surface=8,business_value=7,tech_exposure=8,gate_ease=9,cloud_surface=8,freshness=8
[PRIO] edi2.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi7.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] dtspc-tst.elringklinger.com,7.15,attack_surface=8,business_value=5,tech_exposure=8,gate_ease=8,cloud_surface=7,freshness=8
[PRIO] cctv.elringklinger.com,5.80,attack_surface=6,business_value=5,tech_exposure=6,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] ektrcctv.elringklinger.com,5.80,attack_surface=6,business_value=5,tech_exposure=6,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] fwasvvideo1.elringklinger.com,5.80,attack_surface=6,business_value=5,tech_exposure=6,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] aircontrol.elringklinger.com,5.40,attack_surface=5,business_value=5,tech_exposure=5,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] avconf.elringklinger.com,5.40,attack_surface=5,business_value=5,tech_exposure=5,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] cgline.elringklinger.com,5.40,attack_surface=5,business_value=5,tech_exposure=5,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] imap.elringklinger.com,5.40,attack_surface=5,business_value=5,tech_exposure=5,gate_ease=6,cloud_surface=5,freshness=8
[PRIO] ir.elringklinger.com,4.55,attack_surface=4,business_value=4,tech_exposure=4,gate_ease=9,cloud_surface=3,freshness=6
[HYP] Smartcard API — Broken Auth/IDOR on Versioned Endpoints
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 70
reasoning: Root returns 404 (not 403/401), indicating versioned API paths exist (/api/v1, /v2, /beta). "smartcard" naming implies authentication/access control token issuance, card provisioning, or user-session binding — high-value AUTH target.
evidence_needed: Existence of /api/v1/, /v2/, /swagger.json, /openapi.json endpoints; auth token structure; IDOR on card/user IDs
verify_steps: GET /api/v1/, GET /v2/, GET /swagger.json, GET /openapi.json, GET /api/docs, GET /.well-known/openid-configuration (all HEAD/GET, no auth)
impact: Token forgery, session hijacking, unauthorized card provisioning, privilege escalation — CRITICAL
testability: PASSIVE
[HYP] Events Platform — OAuth Redirect_URI Validation Bypass
class: OATH
asset: go.events.elringklinger.com
confidence: 65
reasoning: HTTP 302 at root indicates redirect-based flow (typical OAuth/SAML/SSO initiation). Event management platforms often integrate corporate SSO; redirect_uri validation flaws allow code theft → ATO.
evidence_needed: OAuth authorize endpoint location; redirect_uri parameter handling; state parameter enforcement; PKCE usage
verify_steps: GET / (follow redirect chain), GET /authorize?client_id=test&redirect_uri=https://evil.com&response_type=code&scope=openid, GET /login (observe IdP), GET /.well-known/oauth-authorization-server (all GET, no auth)
impact: Authorization code theft → full account takeover on linked identities — HIGH
testability: PASSIVE
[HYP] EDI Endpoints — IDOR/BOLA on Partner Document Exchange
class: IDOR
asset: edi2.elringklinger.com
confidence: 60
reasoning: EDI (Electronic Data Interchange) hosts handle B2B document exchange (orders, invoices, ASNs). Multi-tenant EDI platforms frequently expose document IDs in paths (/documents/{id}, /partners/{id}/messages) with missing authorization checks.
evidence_needed: API structure (REST/soap); document/partner ID format; auth model (API key, cert, basic); cross-tenant access control
verify_steps: GET /, GET /api/, GET /v1/, GET /health, GET /actuator/health, GET /docs, GET /swagger.json (all GET/HEAD, no auth)
impact: Cross-partner PII/commercial data disclosure (orders, invoices, pricing), supply chain manipulation — HIGH
testability: PASSIVE
[PARKED] Smartcard API — Broken Auth/IDOR on Versioned Endpoints: confidence 70 ≥ 40, class AUTH not rejected, verify_steps concrete — KEPT
[PARKED] Events Platform — OAuth Redirect_URI Validation Bypass: confidence 65 ≥ 40, class OATH not rejected, verify_steps concrete — KEPT
[PARKED] EDI Endpoints — IDOR/BOLA on Partner Document Exchange: confidence 60 ≥ 40, class IDOR not rejected, verify_steps concrete — KEPT
[FINAL] 1. Smartcard API — Broken Auth/IDOR on Versioned Endpoints (70)
[FINAL] 2. Events Platform — OAuth Redirect_URI Validation Bypass (65)
[FINAL] 3. EDI Endpoints — IDOR/BOLA on Partner Document Exchange (60)
[NEXT] PROBE: GET https://api.smartcard.elringklinger.com/api/v1/ && GET https://api.smartcard.elringklinger.com/v2/ && GET https://api.smartcard.elringklinger.com/swagger.json && GET https://api.smartcard.elringklinger.com/openapi.json && GET https://api.smartcard.elringklinger.com/.well-known/openid-configuration (HEAD/GET only, 1 rps, no auth)
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: 404 at root on API-named host strongly indicates versioned endpoints; auth systems are high-value per directives
[LEARN] ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws are chainable to ATO
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints are documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
[RISK] elringklinger: 72 — 13 dedicated hosts with 3 high-value unprobed API/OAuth/EDI surfaces; zero active testing done; wildcard enum suggests more hidden attack surface; smartcard auth + event OAuth + EDI B2B cover top-3 directive classes (AUTH, OAUTH, IDOR)
## 2026-09-03 19:50:32 UTC [target] (model nemotron3)
[NEW] `api.smartcard.elringklinger.com/api/v1/` returns HTTP 502 (Bad Gateway) — endpoint exists but backend down, confirming versioned API path `/api/v1/` is real
[NEW] `go.events.elringklinger.com/api` returns HTTP 405 for multiple method params — Pardot API endpoint confirmed live, processes auth logic before rejection (error codes 1 vs 49 per earlier finding)
[CHANGED] Probe coverage: 2/13 hosts actively tested (was 0/13)
[PRIO] api.smartcard.elringklinger.com,8.55,attack_surface=9,business_value=9,tech_exposure=9,gate_ease=7,cloud_surface=7,freshness=9
[PRIO] go.events.elringklinger.com,8.10,attack_surface=8,business_value=7,tech_exposure=9,gate_ease=9,cloud_surface=8,freshness=8
[PRIO] edi2.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi7.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] dtspc-tst.elringklinger.com,7.15,attack_surface=8,business_value=5,tech_exposure=8,gate_ease=8,cloud_surface=7,freshness=8
[HYP] Smartcard API — Broken Auth/IDOR on Versioned /api/v1/ Endpoint (Backend Down)
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 80
reasoning: /api/v1/ returns 502 (not 404) proving the versioned endpoint exists and routes to a backend service. "smartcard" naming implies auth token issuance/card provisioning. 502 suggests backend misconfig or downtime — may expose debug info, stack traces, or internal routing on retry/edge cases.
evidence_needed: Response body of 502 (debug trace?); headers revealing framework (Spring, Node, Go); /api/v1/auth, /api/v1/tokens, /api/v1/cards endpoints; JWT/OAuth2 token structure
verify_steps: GET /api/v1/ (capture body/headers), GET /api/v1/health, GET /api/v1/actuator/health, GET /api/v1/auth/login, GET /api/v1/.well-known/openid-configuration, GET /api/v1/swagger.json (all GET/HEAD, no auth)
impact: Token forgery, session hijacking, unauthorized card provisioning, privilege escalation — CRITICAL
testability: PASSIVE
[HYP] Events Platform — Pardot API Method Enumeration + Auth Logic Bypass
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 70
reasoning: /api returns 405 for multiple methods (getCampaigns, getProspects, getEmails) with error code discrimination (1 vs 49) proving auth logic executes pre-rejection. Version param (v2/v3) accepted. 405 suggests methods exist but require POST or valid auth — method enumeration may reveal unauthenticated endpoints.
evidence_needed: Which HTTP methods allowed (POST vs GET); valid method names via enumeration; whether any method returns data without valid api_key/user_key; rate limits
verify_steps: OPTIONS /api, POST /api?api_key=test&method=getProspects&format=json, GET /api?api_key=test&method=getCampaigns&format=json&version=3, GET /api?api_key=test&method=getVersion&format=json (passive, no auth)
impact: Marketing PII disclosure (emails, names, campaign engagement), prospect enumeration — MEDIUM-HIGH
testability: PASSIVE
[HYP] EDI Endpoints — IDOR/BOLA on Partner Document Exchange
class: IDOR
asset: edi2.elringklinger.com
confidence: 60
reasoning: EDI hosts handle B2B document exchange (orders, invoices, ASNs). Multi-tenant EDI platforms frequently expose document IDs in paths (/documents/{id}, /partners/{id}/messages) with missing authorization checks. Both edi2 and edi7 unprobed.
evidence_needed: API structure (REST/soap); document/partner ID format; auth model (API key, cert, basic); cross-tenant access control
verify_steps: GET /, GET /api/, GET /v1/, GET /health, GET /actuator/health, GET /docs, GET /swagger.json (all GET/HEAD, no auth)
impact: Cross-partner PII/commercial data disclosure (orders, invoices, pricing), supply chain manipulation — HIGH
testability: PASSIVE
[PARKED] Smartcard API — Broken Auth/IDOR on Versioned /api/v1/ Endpoint: confidence 80 ≥ 40, class AUTH not rejected, verify_steps concrete — KEPT
[PARKED] Events Platform — Pardot API Method Enumeration + Auth Logic Bypass: confidence 70 ≥ 40, class BUSLOGIC not rejected, verify_steps concrete — KEPT
[PARKED] EDI Endpoints — IDOR/BOLA on Partner Document Exchange: confidence 60 ≥ 40, class IDOR not rejected, verify_steps concrete — KEPT
[FINAL] 1. Smartcard API — Broken Auth/IDOR on Versioned /api/v1/ Endpoint (80)
[FINAL] 2. Events Platform — Pardot API Method Enumeration + Auth Logic Bypass (70)
[FINAL] 3. EDI Endpoints — IDOR/BOLA on Partner Document Exchange (60)
[NEXT] PROBE: GET https://api.smartcard.elringklinger.com/api/v1/ (capture full response body/headers) && GET https://api.smartcard.elringklinger.com/api/v1/health && GET https://api.smartcard.elringklinger.com/api/v1/actuator/health && GET https://api.smartcard.elringklinger.com/api/v1/auth/login && OPTIONS https://go.events.elringklinger.com/api && POST https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json (HEAD/GET/OPTIONS/POST, 1 rps, no auth)
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/ returns 502 confirming versioned endpoint exists with live backend routing — auth systems high-value per directives
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api returns 405 with method-specific error codes (1 vs 49) proving auth logic executes pre-rejection; method enumeration viable
[LEARN] ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws chainable to ATO
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
[RISK] elringklinger: 78 — 13 dedicated hosts with 2 confirmed live high-value APIs (smartcard /api/v1/ 502, Pardot /api 405) + 2 unprobed EDI B2B; active testing now 2/13; smartcard auth + Pardot business logic + EDI IDOR cover top-3 directive classes (AUTH, BUSLOGIC, IDOR); 502 on /api/v1/ may leak debug/stack traces on retry
## 2026-09-03 22:27:21 UTC [target] (model nemotron3)
[NEW] `api.smartcard.elringklinger.com/api/v1/*` all return HTTP 502 (nginx gateway) — backend consistently down, no debug/stack traces leaked in responses
[NEW] `go.events.elringklinger.com/api?method=getCampaigns&version=3` returns HTTP 200 JSON with `err_code:1` (invalid key) — confirms method enumeration works, version param accepted, auth logic executes pre-rejection
[NEW] `go.events.elringklinger.com/api?method=getVersion` returns HTTP 200 JSON with `err_code:1` — version endpoint accessible without valid key
[CHANGED] Pardot API error code discrimination confirmed: `err_code:1` (invalid key) vs earlier `err_code:49` (method not found) — proves method-level auth logic
[CHANGED] Probe coverage: 2/13 hosts tested with deeper endpoint enumeration (was 2/13 basic)
[PRIO] api.smartcard.elringklinger.com,7.80,attack_surface=8,business_value=9,tech_exposure=7,gate_ease=7,cloud_surface=7,freshness=8
[PRIO] go.events.elringklinger.com,8.25,attack_surface=9,business_value=7,tech_exposure=9,gate_ease=9,cloud_surface=8,freshness=9
[PRIO] edi2.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi7.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] dtspc-tst.elringklinger.com,7.15,attack_surface=8,business_value=5,tech_exposure=8,gate_ease=8,cloud_surface=7,freshness=8
[HYP] Smartcard API — Versioned Endpoint Enumeration + Backend Downtime Info Leak
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 65
reasoning: /api/v1/ returns 502 confirming versioned path exists; "smartcard" naming implies auth token/card provisioning; all sub-endpoints (/health, /actuator/health, /auth/login) return identical 502 — consistent backend routing but no debug info leaked. Need to enumerate v2, v3, beta, internal paths and check for framework fingerprints (Spring Boot actuator, Swagger)
evidence_needed: Existence of /api/v2/, /api/beta/, /swagger.json, /openapi.json, /.well-known/openid-configuration; framework headers (Spring, Node, Go); JWT/OAuth2 token structure
verify_steps: GET /api/v2/, GET /api/beta/, GET /api/internal/, GET /swagger.json, GET /openapi.json, GET /.well-known/openid-configuration (all GET/HEAD, no auth)
impact: Token forgery, session hijacking, unauthorized card provisioning — CRITICAL
testability: PASSIVE
[HYP] Events Platform — Pardot API Method Enumeration + Unauthenticated Endpoint Discovery
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 80
reasoning: /api accepts version param (v3 works), returns JSON with err_code discrimination (1=invalid key, 49=method not found per prior finding); OPTIONS returns 200 with Pardot headers; GET getCampaigns+getVersion return 200 JSON proving method enumeration viable; POST getProspects returns 405 suggesting method exists but requires POST. Need to enumerate all Pardot API methods (getProspects, getCampaigns, getEmails, getLists, getTags, getVisitors, getOpportunities, queryProspects) and test which return data without valid api_key/user_key
evidence_needed: Complete method list from Pardot API docs; which methods allow GET vs POST; whether any method returns data with invalid/empty keys; rate limits
verify_steps: GET /api?api_key=test&method=getEmails&format=json&version=3, GET /api?api_key=test&method=getLists&format=json&version=3, GET /api?api_key=test&method=getTags&format=json&version=3, GET /api?api_key=test&method=getVisitors&format=json&version=3, GET /api?api_key=test&method=queryProspects&format=json&version=3 (all GET, no auth)
impact: Marketing PII disclosure (emails, names, campaign engagement, prospect scores), prospect enumeration — MEDIUM-HIGH
testability: PASSIVE
[HYP] EDI Endpoints — IDOR/BOLA on Partner Document Exchange
class: IDOR
asset: edi2.elringklinger.com
confidence: 60
reasoning: EDI hosts (edi2, edi7) handle B2B document exchange (orders, invoices, ASNs). Multi-tenant EDI platforms frequently expose document IDs in paths (/documents/{id}, /partners/{id}/messages) with missing authorization checks. Both hosts completely unprobed — no HTTP status, no tech stack info
evidence_needed: API structure (REST/soap); document/partner ID format; auth model (API key, cert, basic); cross-tenant access control
verify_steps: GET /, GET /api/, GET /v1/, GET /health, GET /actuator/health, GET /docs, GET /swagger.json (all GET/HEAD, no auth)
impact: Cross-partner PII/commercial data disclosure (orders, invoices, pricing), supply chain manipulation — HIGH
testability: PASSIVE
[PARKED] Smartcard API — Versioned Endpoint Enumeration + Backend Downtime Info Leak: confidence 65 ≥ 40, class AUTH not rejected, verify_steps concrete — KEPT
[PARKED] Events Platform — Pardot API Method Enumeration + Unauthenticated Endpoint Discovery: confidence 80 ≥ 40, class BUSLOGIC not rejected, verify_steps concrete — KEPT
[PARKED] EDI Endpoints — IDOR/BOLA on Partner Document Exchange: confidence 60 ≥ 40, class IDOR not rejected, verify_steps concrete — KEPT
[FINAL] 1. Events Platform — Pardot API Method Enumeration + Unauthenticated Endpoint Discovery (80)
[FINAL] 2. Smartcard API — Versioned Endpoint Enumeration + Backend Downtime Info Leak (65)
[FINAL] 3. EDI Endpoints — IDOR/BOLA on Partner Document Exchange (60)
[NEXT] PROBE: GET https://api.smartcard.elringklinger.com/api/v2/ && GET https://api.smartcard.elringklinger.com/api/beta/ && GET https://api.smartcard.elringklinger.com/swagger.json && GET https://api.smartcard.elringklinger.com/openapi.json && GET https://api.smartcard.elringklinger.com/.well-known/openid-configuration && GET https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json&version=3 && GET https://go.events.elringklinger.com/api?api_key=test&method=getLists&format=json&version=3 && GET https://go.events.elringklinger.com/api?api_key=test&method=getTags&format=json&version=3 && GET https://go.events.elringklinger.com/api?api_key=test&method=getVisitors&format=json&version=3 && GET https://go.events.elringklinger.com/api?api_key=test&method=queryProspects&format=json&version=3 (GET/HEAD only, 1 rps, no auth)
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/* returns 502 confirming versioned endpoint exists with live backend routing — auth systems high-value per directives
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api returns 200 JSON with err_code discrimination (1 vs 49) proving auth logic executes pre-rejection; method enumeration viable with version param
[LEARN] ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect on event platform is classic OAuth/SSO initiation pattern; redirect_uri flaws chainable to ATO
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
[RISK] elringklinger: 80 — 13 dedicated hosts with 2 confirmed live high-value APIs (smartcard /api/v1/ 502 backend routing, Pardot /api 200 JSON method enumeration) + 2 unprobed EDI B2B; active testing now 2/13 with deep endpoint coverage; Pardot method enumeration (confidence 80) + smartcard versioned auth (65) + EDI IDOR (60) cover top-3 directive classes (BUSLOGIC, AUTH, IDOR); 502 on smartcard may leak debug on edge/retry; Pardot unauthenticated method discovery is immediate next win
## 2026-09-04 00:30:41 UTC [target] (model nemotron3)
[NEW] api.smartcard.elringklinger.com/api/v2/ and /api/beta/ return HTTP 502 — versioned paths v2/beta exist with same backend routing (nginx gateway), no debug leakage
[NEW] api.smartcard.elringklinger.com/swagger.json, /openapi.json, /.well-known/openid-configuration return HTTP 404 — no OpenAPI/OIDC discovery exposed
[NEW] go.events.elringklinger.com/api?method=getEmails|getLists|getTags|getVisitors|queryProspects all return HTTP 200 JSON with err_code:1 (invalid key) — method enumeration confirmed for 5 additional Pardot methods, all require valid auth
[NEW] go.events.elringklinger.com/ returns HTTP 302 to http://elringklinger.com (HTTP downgrade) with pardot cookie deletion — confirms OAuth/SSO initiation flow with redirect_uri to root domain
[NEW] edi2.elringklinger.com, edi7.elringklinger.com, dtspc-tst.elringklinger.com, aircontrol.elringklinger.com, avconf.elringklinger.com, cctv.elringklinger.com, cgline.elringklinger.com — all connection timeout (8s), no HTTP response
[PRIO] go.events.elringklinger.com,8.25,attack_surface=9,business_value=7,tech_exposure=9,gate_ease=9,cloud_surface=8,freshness=9
[PRIO] api.smartcard.elringklinger.com,7.50,attack_surface=8,business_value=9,tech_exposure=7,gate_ease=6,cloud_surface=7,freshness=8
[PRIO] edi2.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi7.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] dtspc-tst.elringklinger.com,7.15,attack_surface=8,business_value=5,tech_exposure=8,gate_ease=8,cloud_surface=7,freshness=8
[HYP] Events Platform — Pardot OAuth/SSO redirect_uri Validation Flaw
class: OATH
asset: go.events.elringklinger.com
confidence: 75
reasoning: Root path returns 302 to http://elringklinger.com (HTTP downgrade) with pardot cookie deletion; classic OAuth/SSO initiation pattern; redirect_uri points to different domain (elringklinger.com) over HTTP — redirect_uri validation may be lax allowing arbitrary redirect_uri parameter injection
evidence_needed: Whether /login or /auth endpoint accepts redirect_uri parameter; whether redirect_uri validation allows external domains; whether state parameter is enforced
verify_steps: GET https://go.events.elringklinger.com/login?redirect_uri=https://evil.com (capture redirect location), GET https://go.events.elringklinger.com/auth?redirect_uri=https://evil.com, GET https://go.events.elringklinger.com/oauth/authorize?redirect_uri=https://evil.com&client_id=test&response_type=code (all GET, no auth)
impact: OAuth code theft via open redirect -> ATO on event platform -> marketing PII access — HIGH
testability: PASSIVE
[HYP] Smartcard API — Versioned Auth Endpoint Enumeration + Framework Fingerprinting
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 60
reasoning: /api/v1/, /api/v2/, /api/beta/ all return 502 (nginx gateway) confirming versioned routing exists; backend consistently down but routing layer live; "smartcard" naming implies auth token/card provisioning; no Swagger/OpenAPI/OIDC discovery exposed (404); need to identify framework (Spring Boot actuator, Node, Go) for targeted auth attacks
evidence_needed: Framework headers (Server, X-Powered-By); actuator endpoints (/actuator/health, /actuator/env, /actuator/mappings); JWT/OAuth2 token structure; auth endpoint paths (/auth/login, /oauth/token, /login)
verify_steps: GET https://api.smartcard.elringklinger.com/actuator/health, GET https://api.smartcard.elringklinger.com/actuator/env, GET https://api.smartcard.elringklinger.com/actuator/mappings, GET https://api.smartcard.elringklinger.com/auth/login, GET https://api.smartcard.elringklinger.com/oauth/token (all GET/HEAD, no auth)
impact: Token forgery, session hijacking, unauthorized smartcard provisioning — CRITICAL
testability: PASSIVE
[HYP] EDI Endpoints — IDOR/BOLA on Multi-tenant B2B Document Exchange
class: IDOR
asset: edi2.elringklinger.com
confidence: 55
reasoning: EDI hosts (edi2, edi7) handle B2B document exchange (orders, invoices, ASNs); multi-tenant EDI platforms frequently expose document/partner IDs in paths with missing authorization; both hosts completely unprobed (connection timeout); if reachable, likely SOAP/REST APIs with predictable ID patterns
evidence_needed: Live HTTP response; API structure (REST vs SOAP); document/partner ID format; auth model (API key, cert, basic auth); cross-tenant access control on document endpoints
verify_steps: GET https://edi2.elringklinger.com/ (increase timeout to 30s), GET https://edi2.elringklinger.com/api/, GET https://edi2.elringklinger.com/v1/, GET https://edi2.elringklinger.com/health, GET https://edi7.elringklinger.com/ (all GET/HEAD, no auth)
impact: Cross-partner PII/commercial data disclosure (orders, invoices, pricing), supply chain manipulation — HIGH
testability: PASSIVE
[PARKED] EDI Endpoints — IDOR/BOLA on Multi-tenant B2B Document Exchange: confidence 55 ≥ 40, class IDOR not rejected, verify_steps concrete — KEPT but hosts unreachable (timeout) — requires network-level check before meaningful testing
[FINAL] 1. Events Platform — Pardot OAuth/SSO redirect_uri Validation Flaw (75)
[FINAL] 2. Smartcard API — Versioned Auth Endpoint Enumeration + Framework Fingerprinting (60)
[FINAL] 3. EDI Endpoints — IDOR/BOLA on Multi-tenant B2B Document Exchange (55)
[NEXT] PROBE: GET https://go.events.elringklinger.com/login?redirect_uri=https://evil.com && GET https://go.events.elringklinger.com/auth?redirect_uri=https://evil.com && GET https://go.events.elringklinger.com/oauth/authorize?redirect_uri=https://evil.com&client_id=test&response_type=code && GET https://api.smartcard.elringklinger.com/actuator/health && GET https://api.smartcard.elringklinger.com/actuator/env && GET https://api.smartcard.elringklinger.com/actuator/mappings (GET only, 1 rps, no auth)
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/ return 502 confirming versioned endpoint routing exists with live nginx gateway — auth systems high-value per directives
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api method enumeration confirmed for getCampaigns, getVersion, getEmails, getLists, getTags, getVisitors, queryProspects — all return 200 JSON with err_code discrimination (1=invalid key), proving auth logic executes pre-rejection
[LEARN] ACCEPTED OATH @ go.events.elringklinger.com: 302 redirect to http://elringklinger.com (HTTP downgrade) with pardot cookie deletion — classic OAuth/SSO initiation pattern; redirect_uri flaws chainable to ATO
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unreachable (timeout)
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
[RISK] elringklinger: 82 — 13 dedicated hosts with 2 confirmed live high-value APIs (smartcard versioned auth routing 502, Pardot /api 200 JSON method enumeration) + OAuth/SSO redirect flow confirmed + 2 EDI B2B unreachable; active testing now 2/13 with deep coverage; Pardot OAuth redirect_uri (confidence 75) + smartcard versioned auth (60) + EDI IDOR (55) cover top-3 directive classes (OATH, AUTH, IDOR); smartcard backend down but routing layer reveals versioning; Pardot unauthenticated method discovery complete — redirect_uri validation is immediate next win
## 2026-09-04 05:08:41 UTC [target] (model nemotron3)
[NEW] OAuth redirect_uri parameter tested on go.events.elringklinger.com login, auth, oauth/authorize, oauth/token — all ignore/invalidate parameter, redirect fixed to http://elringklinger.com (HTTP downgrade)
[NEW] Smartcard API actuator endpoints (/actuator/health, /actuator/env, /actuator/mappings) all return 404 — not Spring Boot or actuator disabled
[NEW] Smartcard API common auth endpoints (/auth/login, /oauth/token, /login, /health) all return 404
[NEW] Smartcard API framework probes (/metrics, /graphql, /swagger-ui.html) all return 404
[CHANGED] OAuth redirect_uri flaw hypothesis confidence reduced — parameter not reflected in redirect location
[PRIO] go.events.elringklinger.com,7.85,attack_surface=8,business_value=7,tech_exposure=8,gate_ease=9,cloud_surface=8,freshness=9
[PRIO] api.smartcard.elringklinger.com,7.20,attack_surface=7,business_value=9,tech_exposure=6,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi2.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] edi7.elringklinger.com,7.30,attack_surface=7,business_value=9,tech_exposure=7,gate_ease=5,cloud_surface=7,freshness=8
[PRIO] dtspc-tst.elringklinger.com,7.15,attack_surface=8,business_value=5,tech_exposure=8,gate_ease=8,cloud_surface=7,freshness=8
[HYP] Events Platform — Pardot API Unauthenticated Method Enumeration + Version Parameter Access
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 80
reasoning: Pardot /api accepts version=3 parameter; 7 methods (getCampaigns, getVersion, getEmails, getLists, getTags, getVisitors, queryProspects) return 200 JSON with err_code:1 (invalid key) proving auth logic executes pre-rejection; method enumeration works unauthenticated
evidence_needed: Whether any method returns data without valid key; whether version parameter allows access to deprecated/vulnerable API versions; whether rate limiting exists
verify_steps: GET https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=3 (already confirmed 200), GET https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json&version=2, GET https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=1 (test version downgrade)
impact: API surface mapping, potential version downgrade to less protected endpoints, method enumeration for targeted auth bypass — MEDIUM
testability: PASSIVE
[HYP] Smartcard API — Versioned Auth Endpoint Enumeration + Backend Framework Identification
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 55
reasoning: /api/v1/, /api/v2/, /api/beta/ all return 502 (nginx gateway) confirming versioned routing; backend consistently down; no Spring Boot actuator, no common auth endpoints, no GraphQL/Swagger; "smartcard" naming implies token/card provisioning auth system; framework unknown
evidence_needed: Framework identification headers (X-Powered-By, Server beyond nginx); any non-404 endpoint under /api/v1/*; JWT/OAuth2 token structure if auth endpoints found; backend technology stack
verify_steps: GET https://api.smartcard.elringklinger.com/api/v1/ (capture full headers/body), GET https://api.smartcard.elringklinger.com/api/v2/, GET https://api.smartcard.elringklinger.com/api/beta/ (all GET, no auth)
impact: Token forgery, session hijacking, unauthorized smartcard provisioning — CRITICAL
testability: PASSIVE
[HYP] EDI Endpoints — IDOR/BOLA on Multi-tenant B2B Document Exchange
class: IDOR
asset: edi2.elringklinger.com
confidence: 50
reasoning: EDI hosts (edi2, edi7) handle B2B document exchange; multi-tenant EDI platforms frequently expose document/partner IDs with missing authorization; both hosts unreachable (connection timeout 8s); if reachable, likely SOAP/REST APIs with predictable ID patterns
evidence_needed: Live HTTP response; API structure (REST vs SOAP); document/partner ID format; auth model (API key, cert, basic auth); cross-tenant access control on document endpoints
verify_steps: GET https://edi2.elringklinger.com/ (increase timeout to 30s), GET https://edi2.elringklinger.com/api/, GET https://edi2.elringklinger.com/v1/, GET https://edi2.elringklinger.com/health, GET https://edi7.elringklinger.com/ (all GET/HEAD, no auth)
impact: Cross-partner PII/commercial data disclosure (orders, invoices, pricing), supply chain manipulation — HIGH
testability: PASSIVE
[PARKED] Events Platform — Pardot OAuth/SSO redirect_uri Validation Flaw: confidence dropped to 35 — redirect_uri parameter tested on 4 endpoints (login, auth, oauth/authorize, oauth/token), all ignore parameter and redirect fixed to http://elringklinger.com; no open redirect
[PARKED] EDI Endpoints — IDOR/BOLA on Multi-tenant B2B Document Exchange: confidence 50 ≥ 40 but hosts unreachable (timeout) — requires network-level check before meaningful testing
[FINAL] 1. Events Platform — Pardot API Unauthenticated Method Enumeration + Version Parameter Access (80)
[FINAL] 2. Smartcard API — Versioned Auth Endpoint Enumeration + Backend Framework Identification (55)
[NEXT] PROBE: GET https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=2 && GET https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=1 && GET https://api.smartcard.elringklinger.com/api/v1/ && GET https://api.smartcard.elringklinger.com/api/v2/ && GET https://api.smartcard.elringklinger.com/api/beta/ (GET only, 1 rps, no auth, capture full headers/body)
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot /api method enumeration confirmed for 7 methods (getCampaigns, getVersion, getEmails, getLists, getTags, getVisitors, queryProspects) — all return 200 JSON with err_code:1 (invalid key), proving auth logic executes pre-rejection; version=3 parameter accepted
[LEARN] REJECTED OATH @ go.events.elringklinger.com: OAuth redirect_uri parameter tested on login, auth, oauth/authorize, oauth/token — all ignore parameter, redirect fixed to http://elringklinger.com (HTTP downgrade); no open redirect via redirect_uri
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: /api/v1/, /api/v2/, /api/beta/ return 502 confirming versioned endpoint routing exists with live nginx gateway — no Spring Boot actuator, no common auth endpoints exposed, framework unidentified
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B endpoints documented IDOR/BOLA hotspots; multi-tenant document exchange fits directive — but hosts currently unreachable (timeout)
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives
[RISK] elringklinger: 78 — 13 dedicated hosts with 2 confirmed live high-value APIs (Pardot /api 200 JSON method enumeration + version param, smartcard versioned auth routing 502 nginx gateway) + 2 EDI B2B unreachable; active testing 2/13; Pardot method enumeration (80) + smartcard versioned auth (55) cover top directive classes (BUSLOGIC, AUTH); OAuth redirect_uri flaw disproven; smartcard backend down but versioned routing confirmed; Pardot version parameter downgrade testing is immediate next win
