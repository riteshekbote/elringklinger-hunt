
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
