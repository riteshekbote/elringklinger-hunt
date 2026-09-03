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
