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
