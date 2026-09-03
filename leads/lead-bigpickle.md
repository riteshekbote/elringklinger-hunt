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
