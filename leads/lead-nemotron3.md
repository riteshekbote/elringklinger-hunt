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
