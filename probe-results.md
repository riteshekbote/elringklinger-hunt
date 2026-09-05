
## 2026-09-02 21:46:45 UTC


## 2026-09-02 23:58:57 UTC


## 2026-09-03 03:39:30 UTC


## 2026-09-03 08:19:54 UTC


## 2026-09-03 12:54:04 UTC


## 2026-09-03 17:07:02 UTC
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/v2/ -> HTTP 404
https://api.smartcard.elringklinger.com/swagger.json -> HTTP 404
https://api.smartcard.elringklinger.com/openapi.json -> HTTP 404
https://api.smartcard.elringklinger.com/.well-known/openid-configuration -> HTTP 404
https://go.events.elringklinger.com/api?api_key=test&format=json&version=2` -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getProspects` -> HTTP 405
https://go.events.elringklinger.com/api?user_key=test&api_key=test` -> HTTP 405
https://go.events.elringklinger.com/?pi_campaign=testcampaign` -> 200 len=210594
https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json -> HTTP 405

## 2026-09-03 19:51:08 UTC
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/health -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/actuator/health -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/auth/login -> HTTP 502
https://go.events.elringklinger.com/api -> HTTP 401
https://go.events.elringklinger.com/api?api_key=test&method=getProspects&format=json -> HTTP 405
https://api.smartcard.elringklinger.com/api/v2/ -> HTTP 502
https://api.smartcard.elringklinger.com/v1/ -> HTTP 404
https://api.smartcard.elringklinger.com/swagger -> HTTP 404
https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json -> HTTP 405
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>

## 2026-09-03 22:27:50 UTC
https://api.smartcard.elringklinger.com/api/v2/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/beta/ -> HTTP 502
https://api.smartcard.elringklinger.com/swagger.json -> HTTP 404
https://api.smartcard.elringklinger.com/openapi.json -> HTTP 404
https://api.smartcard.elringklinger.com/.well-known/openid-configuration -> HTTP 404
https://go.events.elringklinger.com/api?api_key=test&method=getEmails&format=json&version=3 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getLists&format=json&version=3 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getTags&format=json&version=3 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getVisitors&format=json&version=3 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=queryProspects&format=json&version=3 -> HTTP 405
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/v1/ -> HTTP 404

## 2026-09-04 00:32:39 UTC
https://go.events.elringklinger.com/login?redirect_uri=https://evil.com -> 200 len=210594
https://go.events.elringklinger.com/auth?redirect_uri=https://evil.com -> 200 len=210594
https://go.events.elringklinger.com/oauth/authorize?redirect_uri=https://evil.com&client_id=test&response_type=code -> 200 len=210594
https://api.smartcard.elringklinger.com/actuator/health -> HTTP 404
https://api.smartcard.elringklinger.com/actuator/env -> HTTP 404
https://api.smartcard.elringklinger.com/actuator/mappings -> HTTP 404
https://api.smartcard.elringklinger.com/auth/login -> HTTP 404
https://api.smartcard.elringklinger.com/oauth/token -> HTTP 404
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/v1/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/health -> ERR <urlopen error timed out>

## 2026-09-04 05:17:05 UTC
https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=3 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getCampaigns&format=json&version=2 -> HTTP 405
https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=1 -> HTTP 405
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/v2/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/beta/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/v1/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/health -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>
https://go.events.elringklinger.com/api?api_key=test&method=getVersion&format=json&version=2 -> HTTP 405

## 2026-09-04 09:49:04 UTC
https://go.events.elringklinger.com/api/v5/campaign -> HTTP 401
https://go.events.elringklinger.com/api/v5/prospect -> HTTP 401
https://go.events.elringklinger.com/api/v5/ -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/auth -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/tokens -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/cards -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/health -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/v1/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/health -> ERR <urlopen error timed out>

## 2026-09-04 14:13:48 UTC
https://go.events.elringklinger.com/api/v5/emails -> HTTP 401
https://go.events.elringklinger.com/api/v5/lists -> HTTP 401
https://go.events.elringklinger.com/api/v5/tags -> HTTP 401
https://go.events.elringklinger.com/api/v5/visitors -> HTTP 401
https://go.events.elringklinger.com/api/v5/prospects -> HTTP 401
https://go.events.elringklinger.com/api/v5/campaigns -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/auth -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/tokens -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/cards -> HTTP 502
https://api.smartcard.elringklinger.com/api/v1/health -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>

## 2026-09-04 17:49:24 UTC
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/v1/ -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>

## 2026-09-04 20:07:30 UTC
https://go.events.elringklinger.com/api?method=getVersion&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getCampaigns&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=queryProspects&version=3 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>
https://go.events.elringklinger.com/api?method=getEmails&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getLists&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getTags&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVisitors&version=3 -> HTTP 401
https://api.smartcard.elringklinger.com/v2/ -> HTTP 404

## 2026-09-04 22:17:19 UTC
https://go.events.elringklinger.com/api?method=getVersion&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getCampaigns&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=queryProspects&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getEmails&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getLists&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getTags&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVisitors&version=3 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>
https://api.smartcard.elringklinger.com/api/v1/` -> HTTP 502

## 2026-09-05 00:14:37 UTC
https://go.events.elringklinger.com/api?method=getVersion&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getCampaigns&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=queryProspects&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getEmails&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getLists&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getTags&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVisitors&version=3 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>
https://api.smartcard.elringklinger.com/api/v1/` -> HTTP 502

## 2026-09-05 04:43:22 UTC
https://go.events.elringklinger.com/api?method=getVersion&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getCampaigns&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=queryProspects&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getEmails&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getLists&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getTags&version=3 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVisitors&version=3 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://edi2.elringklinger.com/ -> ERR <urlopen error timed out>
https://edi2.elringklinger.com/api/ -> ERR <urlopen error timed out>
https://edi7.elringklinger.com/ -> ERR <urlopen error timed out>
https://go.events.elringklinger.com/api/v5/prospects` -> HTTP 401

## 2026-09-05 08:47:53 UTC
https://go.events.elringklinger.com/api/v5/prospects -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=1 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502
https://go.events.elringklinger.com/api/v5/prospects` -> HTTP 401

## 2026-09-05 12:24:16 UTC
https://go.events.elringklinger.com/api/v5/prospects` -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502

## 2026-09-05 15:25:25 UTC
https://go.events.elringklinger.com/api/v5/prospects -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=1 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=2 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=4 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=5 -> HTTP 401
https://api.smartcard.elringklinger.com/api/v1/ -> HTTP 502

## 2026-09-05 17:41:35 UTC
https://go.events.elringklinger.com/api/v5/prospects -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=1 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=2 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=4 -> HTTP 401
https://go.events.elringklinger.com/api?method=getVersion&version=5 -> HTTP 401
https://go.events.elringklinger.com/api/v5/oauth/token` -> HTTP 401
