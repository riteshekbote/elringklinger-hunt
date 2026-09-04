## 2026-09-03 17:05:00 UTC [target] (model bigpickle)
[HYP] Pardot API version/format enumeration + info disclosure
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 65
reasoning: Pardot API at `/api` is live and returns structured XML/JSON errors. Version param accepted (v2/v3 both return "Invalid API key or user key"). `format=json` switches response format. The API distinguishes "Invalid API key or user key" (err_code 1) from "Access Denied" (err_code 49) — different error codes for different failure modes suggest the API logic processes auth before rejecting. If any legacy Pardot API endpoint allows unauthenticated read (e.g. prospect lookup by email, campaign list), it would leak PII/marketing data.
evidence_needed: Authenticated Pardot API key (from Salesforce/Pardot admin). Without valid key, only error discrimination observable.
verify_steps: PASSIVE: `curl https://go.events.elringklinger.com/api?api_key=test&format=json&version=2` (done). `curl https://go.events.elringklinger.com/api?api_key=test&method=getProspects` to test method enumeration. `curl https://go.events.elringklinger.com/api?user_key=test&api_key=test` to test dual-key auth.
impact: If legacy Pardot API allows unauthenticated access → marketing PII (emails, names, campaign engagement). Severity: MEDIUM-HIGH if exploitable.
testability: AUTH_HELPED
[HYP] Pardot HTTP downgrade enables cookie injection on event tracking links
class: MISCONFIG
asset: go.events.elringklinger.com
confidence: 55
reasoning: Root path 302 redirects to `http://elringklinger.com` (plain HTTP). The Pardot tracking cookie (`pardot`) is set with no Secure flag and cleared on every request. If an attacker can craft a tracking link (e.g. via Pardot campaign URL), the initial HTTP response could be intercepted/modified before the redirect completes. The redirect target `http://elringklinger.com` itself redirects to HTTPS, but the intermediate HTTP hop is attacker-controllable on shared networks.
evidence_needed: Confirm the redirect is triggered by campaign tracking URLs (pi_campaign, pi_aid params). Test if Pardot tracking cookie is set during the HTTP redirect chain.
verify_steps: PASSIVE: `curl -D- https://go.events.elringklinger.com/?pi_campaign=testcampaign` — check if cookie is set on the 302 response. `curl -D- http://elringklinger.com/` — confirm HTTP→HTTPS redirect.
impact: Attacker on same network can inject cookies or modify redirect content before HTTPS upgrade. Severity: LOW-MEDIUM (requires network position).
testability: PASSIVE
[HYP] TYPO3 backend exposed — version fingerprinting + session nonce predictability
class: MISCONFIG
asset: elringklinger.de
confidence: 45
reasoning: TYPO3 login page fully accessible at `/typo3/index.php` and `/typo3/login` (200). Backend CSS assets expose TYPO3 version hints (asset hashes `1786432642`, `1786465520` — likely Unix timestamps from build). JWT nonce cookie uses HS256 with `nonce`+`time` claims — the nonce is a random string, time is the issue time. This is standard TYPO3 security behavior, but the exposed login panel itself is an attack surface for credential stuffing (if lockout policy is weak — though that's out of scope per program). The `typo3temp/` directory is accessible (200) and may leak cached files.
evidence_needed: Enumerate `typo3temp/` subdirectories for leaked files. Check TYPO3 version from asset timestamps. Test if `typo3conf/` contains any accessible config files.
verify_steps: PASSIVE: `curl https://elringklinger.de/typo3temp/assets/` — list contents. `curl https://elringklinger.de/typo3conf/` (already 403). Check `/_assets/` paths for version info.
impact: TYPO3 version disclosure → known CVE mapping. Exposed admin panel → credential stuffing target. Severity: LOW (login panel is expected per program scope exclusion).
testability: PASSIVE
[NEXT] PROBE: Test Pardot API method enumeration to discover accessible endpoints — exact request: `curl -sS --max-time 8 "https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json"` and `curl -sS --max-time 8 "https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json"` and `curl -sS --max-time 8 "https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json"` — check if different methods return different error codes (would indicate method existence).
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error code discrimination (1 vs 49) confirms API processes auth logic before rejection. Method enumeration may reveal which endpoints exist.
[LEARN] REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
[LEARN] ACCEPTED MISCONFIG @ go.events.elringklinger.com: HTTP downgrade redirect is real but low-severity. Worth tracking as chain primitive (e.g. combined with phishing).
[RISK] elringklinger: 25/100. Surface is thin — 13 dedicated hosts, 9 unreachable, 2 with HTTP, 1 TYPO3 CMS with standard admin. No high-value APIs accessible without auth. Program scope is broad ("all company-owned infrastructure") but actual discoverable attack surface is limited. Best bet is Pardot API method enumeration or finding additional subdomains via CT/DNS not yet discovered.
## 2026-09-03 19:44:15 UTC [target] (model bigpickle)
[PRIO] api.smartcard.elringklinger.com, 7.8, surface=8(auth/API), value=8(PHI/credentials), tech=9(versioned API), gate=6(requires valid API key), cloud=3, freshness=7
[PRIO] go.events.elringklinger.com, 6.5, surface=7(Pardot+OAuth), value=7(marketing PII), tech=8(OAuth flow), gate=5(Pardot API key), cloud=2, freshness=6
[PRIO] edi2.elringklinger.com, 6.2, surface=7(EDI/B2B), value=8(business docs), tech=6(EDI protocols), gate=4(multi-tenant), cloud=1, freshness=5
[PRIO] edi7.elringklinger.com, 5.8, surface=6(EDI), value=7(business docs), tech=5, gate=4, cloud=1, freshness=5
[PRIO] cctv.elringklinger.com, 4.5, surface=5(CCTV), value=5(surveillance), tech=4, gate=3(local auth), cloud=2, freshness=4
[HYP] Smartcard API versioned endpoint enumeration via path traversal
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 72
reasoning: Root returns 404, suggesting versioned paths (/api/v1/, /api/v2/, /v1/, /v2/). API-named host on dedicated IP implies internal authentication system. Versioned endpoints often expose different auth requirements or legacy unprotected paths.
evidence_needed: HTTP response from GET /api/, /api/v1/, /api/v2/, /v1/, /v2/, /swagger, /openapi.json
verify_steps: PASSIVE: GET https://api.smartcard.elringklinger.com/api/v1/, GET https://api.smartcard.elringklinger.com/api/v2/, GET https://api.smartcard.elringklinger.com/v1/, GET https://api.smartcard.elringklinger.com/swagger
impact: Unauthenticated access to smartcard provisioning/management API → credential theft, identity fraud. Severity: HIGH if exploitable.
testability: PASSIVE
[HYP] Pardot API method enumeration reveals accessible marketing data endpoints
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 68
reasoning: Pardot API distinguishes between "Invalid API key" (err_code 1) and "Access Denied" (err_code 49), indicating method-level authorization. Different methods may exist with varying auth requirements. Method names like getCampaigns, getProspects, getEmails are standard Pardot endpoints.
evidence_needed: Different error responses (code 1 vs 49) for different method names
verify_steps: PASSIVE: GET https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json, GET https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json, GET https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json
impact: Marketing PII (emails, names, campaign engagement), segmentation data. Severity: MEDIUM-HIGH if unauthenticated methods exist.
testability: PASSIVE
[HYP] EDI endpoint cross-tenant document access via IDOR
class: IDOR
asset: edi2.elringklinger.com
confidence: 58
reasoning: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange with sequential IDs or predictable reference numbers could allow cross-tenant access. edi7.elringklinger.com (likely newer version) may have different auth implementation.
evidence_needed: Document listing endpoint with ID/uid parameters, error responses for invalid document references
verify_steps: PASSIVE: GET https://edi2.elringklinger.com/, GET https://edi7.elringklinger.com/, HEAD both for server headers/tech stack
impact: Access to purchase orders, invoices, shipping documents across tenants. Severity: MEDIUM (requires valid tenant credentials to test).
testability: AUTH_HELPED
[FINAL] Smartcard API versioned endpoint enumeration: 72 confidence, PASSIVE testability, HIGH impact. Survives.
[FINAL] Pardot API method enumeration: 68 confidence, PASSIVE testability, MEDIUM-HIGH impact. Survives.
[FINAL] EDI IDOR: 58 confidence, AUTH_HELPED testability, MEDIUM impact. Survives but lower priority without auth context.
[PARKED] CCTV endpoint analysis: 4.5 priority score, likely requires local network access, LOW business value relative to API/auth systems. Parking for now.
[NEXT] PROBE: Test Smartcard API versioned endpoints with exact requests:
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: Versioned endpoints likely exist based on 404 at root. Auth systems are high-value targets per directives.
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error discrimination confirms method-level authorization logic. Enumeration may reveal accessible endpoints.
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange fits program scope.
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives.
[LEARN] REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
[RISK] elringklinger: 65/100. Surface is moderate — 13 dedicated hosts, 3 with HTTP responses, 1 API endpoint returning 404 (likely versioned). Program scope is broad ("all company-owned infrastructure") but discoverable attack surface is limited to:
## 2026-09-03 22:25:10 UTC [target] (model bigpickle)
[NEW] `api.smartcard.elringklinger.com/api/v1/` returns HTTP 502 — live backend, versioned path confirmed
[NEW] `go.events.elringklinger.com/api` returns HTTP 405 with method-specific error codes (1 vs 49) — Pardot API live
[CHANGED] Probe coverage: 2/13 hosts actively tested (was 0/13)
[PRIO] api.smartcard.elringklinger.com, 7.8, surface=8(auth/API), value=8(PHI/credentials), tech=9(versioned API), gate=6(requires valid API key), cloud=3, freshness=7
[PRIO] go.events.elringklinger.com, 6.5, surface=7(Pardot+OAuth), value=7(marketing PII), tech=8(OAuth flow), gate=5(Pardot API key), cloud=2, freshness=6
[PRIO] edi2.elringklinger.com, 6.2, surface=7(EDI/B2B), value=8(business docs), tech=6(EDI protocols), gate=4(multi-tenant), cloud=1, freshness=5
[PRIO] edi7.elringklinger.com, 5.8, surface=6(EDI), value=7(business docs), tech=5, gate=4, cloud=1, freshness=5
[PRIO] cctv.elringklinger.com, 4.5, surface=5(CCTV), value=5(surveillance), tech=4, gate=3(local auth), cloud=2, freshness=4
[HYP] Smartcard API versioned endpoint enumeration via path traversal
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 72
reasoning: Root returns 404, suggesting versioned paths (/api/v1/, /api/v2/, /v1/, /v2/). API-named host on dedicated IP implies internal authentication system. Versioned endpoints often expose different auth requirements or legacy unprotected paths.
evidence_needed: HTTP response from GET /api/, /api/v1/, /api/v2/, /v1/, /v2/, /swagger, /openapi.json
verify_steps: PASSIVE: GET https://api.smartcard.elringklinger.com/api/v1/, GET https://api.smartcard.elringklinger.com/api/v2/, GET https://api.smartcard.elringklinger.com/v1/, GET https://api.smartcard.elringklinger.com/swagger
impact: Unauthenticated access to smartcard provisioning/management API → credential theft, identity fraud. Severity: HIGH if exploitable.
testability: PASSIVE
[HYP] Pardot API method enumeration reveals accessible marketing data endpoints
class: BUSLOGIC
asset: go.events.elringklinger.com
confidence: 68
reasoning: Pardot API distinguishes between "Invalid API key" (err_code 1) and "Access Denied" (err_code 49), indicating method-level authorization. Different methods may exist with varying auth requirements. Method names like getCampaigns, getProspects, getEmails are standard Pardot endpoints.
evidence_needed: Different error responses (code 1 vs 49) for different method names
verify_steps: PASSIVE: GET https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json, GET https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json, GET https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json
impact: Marketing PII (emails, names, campaign engagement), segmentation data. Severity: MEDIUM-HIGH if unauthenticated methods exist.
testability: PASSIVE
[HYP] EDI endpoint cross-tenant document access via IDOR
class: IDOR
asset: edi2.elringklinger.com
confidence: 58
reasoning: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange with sequential IDs or predictable reference numbers could allow cross-tenant access. edi7.elringklinger.com (likely newer version) may have different auth implementation.
evidence_needed: Document listing endpoint with ID/uid parameters, error responses for invalid document references
verify_steps: PASSIVE: GET https://edi2.elringklinger.com/, GET https://edi7.elringklinger.com/, HEAD both for server headers/tech stack
impact: Access to purchase orders, invoices, shipping documents across tenants. Severity: MEDIUM (requires valid tenant credentials to test).
testability: AUTH_HELPED
[FINAL] Smartcard API versioned endpoint enumeration: 72 confidence, PASSIVE testability, HIGH impact. Survives.
[FINAL] Pardot API method enumeration: 68 confidence, PASSIVE testability, MEDIUM-HIGH impact. Survives.
[FINAL] EDI IDOR: 58 confidence, AUTH_HELPED testability, MEDIUM impact. Survives but lower priority without auth context.
[PARKED] CCTV endpoint analysis: 4.5 priority score, likely requires local network access, LOW business value relative to API/auth systems. Parking for now.
[NEXT] PROBE: Test Smartcard API versioned endpoints with exact requests:
[LEARN] ACCEPTED AUTH @ api.smartcard.elringklinger.com: Versioned endpoints likely exist based on 404 at root. Auth systems are high-value targets per directives.
[LEARN] ACCEPTED BUSLOGIC @ go.events.elringklinger.com: Pardot API error discrimination confirms method-level authorization logic. Enumeration may reveal accessible endpoints.
[LEARN] ACCEPTED IDOR @ edi2.elringklinger.com: EDI/B2B systems are documented IDOR hotspots. Multi-tenant document exchange fits program scope.
[LEARN] REJECTED OTHER @ ir.elringklinger.com: Static investor relations page (Apache 301) — low attack surface, no auth/API/upload surface per directives.
[LEARN] REJECTED MISCONFIG @ elringklinger.de (TYPO3 login): Program scope explicitly excludes public login panels and brute-force policy. No finding.
[RISK] elringklinger: 65/100. Surface is moderate — 13 dedicated hosts, 3 with HTTP responses, 1 API endpoint returning 404 (likely versioned). Program scope is broad ("all company-owned infrastructure") but discoverable attack surface is limited to 3 active targets (Smartcard API, Pardot API, EDI). No high-value APIs accessible without auth. Best bet is versioned endpoint enumeration on Smartcard API or finding unprotected Pardot methods.
## 2026-09-04 00:25:14 UTC [target] (model bigpickle)
[HYP] Smartcard API backend-downtime information disclosure via gateway headers
[HYP] Smartcard API versioned endpoint recovery when backend returns online
class: AUTH
asset: api.smartcard.elringklinger.com
confidence: 48
reasoning: /api/v1/* uniformly 502 (nginx gateway, backend down). Swagger/openapi/docs/health all 404/502. Backend intermittently online would allow auth probe; current state is unreachable backend, not unprotected endpoint.
evidence_needed: backend transition from 502 to 200/401/403 JSON on /api/v1/ paths
verify_steps: PASSIVE: re-GET https://api.smartcard.elringklinger.com/api/v1/ at intervals (<=1 rps), check for non-502 status
impact: unauthenticated access to smartcard provisioning API → credential/identity theft. Severity HIGH if backend live.
testability: AUTH_HELPED (blocked by backend outage)
[PARKED] Pardot method enumeration: all methods return err_code:1 invalid key regardless of method name/version — no unauthenticated method exists; requires valid API key (not available). Confidence dropped to <40.
[PARKED] EDI cross-tenant IDOR: edi2/edi7 time out on external HTTPS — no reachable endpoint to test; requires tenant auth. Confidence <40.
[PARKED] go.events OAuth redirect_uri: all paths hardcode 302 → http://elringklinger.com, no param reflection. Closed.
## 2026-09-04 05:15:40 UTC [target] (model bigpickle)
[HYP] Pardot v5 API tier exposes distinct auth-gated endpoints with different key/credential requirements
class: AUTH
asset: go.events.elringklinger.com/api/v5
confidence: 42
reasoning: v5 returns HTTP 401 "Access Denied" ({code:49}) while v1-v4 return JSON err_code 49/198 regardless — v5 is a separately-routed API tier that may accept OAuth bearer vs legacy API keys, potentially with different IDOR posture on GET resource methods.
evidence_needed: a v5 endpoint returning a resource (200) instead of 401/198/1; or a 401 differing between methods to indicate per-method authz
verify_steps: PASSIVE: GET https://go.events.elringklinger.com/api/v5/{resource} for resource in campaign, prospect, user, visitor, account, list, folder, tag; compare status codes
impact: If any v5 resource responds without credentials → marketing PII / campaign data exposure. Severity MEDIUM-HIGH.
testability: PASSIVE
[NEXT] PROBE: GET https://go.events.elringklinger.com/api/v5/campaign, GET https://go.events.elringklinger.com/api/v5/prospect, GET https://go.events.elringklinger.com/api/v5/user, GET https://go.events.elringklinger.com/api/v5/visitor (compare 401 vs resource response)
[RISK] elringklinger: 34/100. All 13 dedicated hosts are either backend-down (Smartcard API, 502), auth-gated + redirect-hardcoded (Pardot), or unreachable from external (EDI, CCTV, IMAP, all infra). Production domain elringklinger.de is now timing out. The remaining live surface (Pardot tracking + auth-gated API) exposes no unauthenticated data path after exhaustive enumeration of ~20 API methods, v1-v5 tiers, tracking endpoints, and redirect vectors. Only weak survivor is v5 API tier enumeration (42 confidence). No real logic flaw identified; surface is a dead end until Smartcard backend or EDI hosts come online within reach.
