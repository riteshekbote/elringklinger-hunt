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
