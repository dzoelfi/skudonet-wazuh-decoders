# General Info

This simple decoder was created to decode Skudonet WAF syslog on Wazuh since there is no official decoder that provided by Wazuh.

This project inspired by ModSecurity WAF Log decoder since it has similar pattern log to Skudonet WAF Ruleset Log

# Requirement

To ensure Skudonet WAF Log well decoded, please make sure you enable:
- Wazuh archive log
- Rsyslog on Skudonet WAF Machine and Wazuh Server

# Expected output

Here you can see sample log and how the output

> Dec 26 06:04:17 waf-skudonet pound: Farm-https, service wazuh-dashboard, backend 192.168.200.53:443, (7efc4d7586c0) WAF denied a request from 172.70.208.39

    **Phase 1: Completed pre-decoding.
	    full event: 'Dec 26 06:04:17 waf-skudonet pound: Farm-https, service wazuh-dashboard, backend 192.168.200.53:443, (7efc4d7586c0) WAF denied a request from 172.70.208.39'
	    timestamp: 'Dec 26 06:04:17'
	    hostname: 'waf-skudonet'
	    program_name: 'pound'

    **Phase 2: Completed decoding.
	    name: 'skudonet'
	    action: 'denied a request from 172.70.208.39'
	    dstip: '192.168.200.53'
	    farm: 'Farm-https'
	    service: 'wazuh-dashboard'
	    srcip: '172.70.208.39'

    **Phase 3: Completed filtering (rules).
	    id: '200002'
	    level: '4'
	    description: 'Log WAF Skudonet'
	    groups: '["skudonet"," waf"," syslog"]'
	    firedtimes: '1'
	    mail: 'false'
---
> 
> Dec 26 06:04:17 waf-skudonet pound: Farm-https, [WAF,service wazuh-dashboard, backend 192.168.200.53:443,] (7efc4d7586c0) [client 172.70.208.39] SKUDONET ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/usr/local/skudonet/config/ipds/waf/sets/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "231"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data "client:172.70.208.39"] [severity "0"] [ver "OWASP_CRS/4.9.0-dev"] [maturity "0"] [accuracy "0"] [tag "anomaly-evaluation"] [tag "OWASP_CRS"] [hostname "123.123.113.123"] [uri "/api/saved_objects/index-pattern/wazuh-alerts-*"] [unique_id "173516785757.173389"] [ref ""]

    **Phase 1: Completed pre-decoding.
	    full event: 'Dec 26 06:04:17 waf-skudonet pound: Farm-https, [WAF,service wazuh-dashboard, backend 192.168.200.53:443,] (7efc4d7586c0) [client 172.70.208.39] SKUDONET ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/usr/local/skudonet/config/ipds/waf/sets/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "231"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data "client:172.70.208.39"] [severity "0"] [ver "OWASP_CRS/4.9.0-dev"] [maturity "0"] [accuracy "0"] [tag "anomaly-evaluation"] [tag "OWASP_CRS"] [hostname "123.123.113.123"] [uri "/api/saved_objects/index-pattern/wazuh-alerts-*"] [unique_id "173516785757.173389"] [ref ""]'
	    timestamp: 'Dec 26 06:04:17'
	    hostname: 'waf-skudonet'
	    program_name: 'pound'

    **Phase 2: Completed decoding.
	    name: 'skudonet'
	    descriptions: '"Inbound Anomaly Score Exceeded (Total Score: 5)"'
	    dstip: '192.168.200.53'
	    farm: 'Farm-https'
	    service: 'wazuh-dashboard'
	    srcip: '172.70.208.39'
	    type: 'Access denied with code 403 (phase 2)'

    **Phase 3: Completed filtering (rules).
	    id: '200002'
	    level: '4'
	    description: 'Log WAF Skudonet'
	    groups: '["skudonet"," waf"," syslog"]'
	    firedtimes: '1'
	    mail: 'false'
---
>
> Dec 26 06:04:17 waf-skudonet pound: Farm-https, SKUDONET ModSecurity: Warning. Matched "Operator `Within' with parameter `GET HEAD POST OPTIONS' against variable `REQUEST_METHOD' (Value: `PUT' ) [file "/usr/local/skudonet/config/ipds/waf/sets/REQUEST-911-METHOD-ENFORCEMENT.conf"] [line "37"] [id "911100"] [rev ""] [msg "Method is not allowed by policy"] [data "PUT"] [severity "2"] [ver "OWASP_CRS/4.9.0-dev"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272/220/274"] [tag "PCI/12.1"] [hostname "123.123.113.123"] [uri "/api/saved_objects/index-pattern/wazuh-alerts-*"] [unique_id "173516785757.173389"] [ref "v0,3"]

    **Phase 1: Completed pre-decoding.
	    full event: 'Dec 26 06:04:17 waf-skudonet pound: Farm-https, SKUDONET ModSecurity: Warning. Matched "Operator `Within' with parameter `GET HEAD POST OPTIONS' against variable `REQUEST_METHOD' (Value: `PUT' ) [file "/usr/local/skudonet/config/ipds/waf/sets/REQUEST-911-METHOD-ENFORCEMENT.conf"] [line "37"] [id "911100"] [rev ""] [msg "Method is not allowed by policy"] [data "PUT"] [severity "2"] [ver "OWASP_CRS/4.9.0-dev"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272/220/274"] [tag "PCI/12.1"] [hostname "123.123.113.123"] [uri "/api/saved_objects/index-pattern/wazuh-alerts-*"] [unique_id "173516785757.173389"] [ref "v0,3"]'
	    timestamp: 'Dec 26 06:04:17'
	    hostname: 'waf-skudonet'
	    program_name: 'pound'

    **Phase 2: Completed decoding.
	    name: 'skudonet'
	    descriptions: '"Method is not allowed by policy"'
	    farm: 'Farm-https'
	    type: 'Warning'

    **Phase 3: Completed filtering (rules).
	    id: '200002'
	    level: '4'
	    description: 'Log WAF Skudonet'
	    groups: '["skudonet"," waf"," syslog"]'
	    firedtimes: '1'
	    mail: 'false'

# References
- [Creating decoders and rules from scratch](https://wazuh.com/blog/creating-decoders-and-rules-from-scratch/)
- [Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
- [Sibling Decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html)
- [Wazuh’s Rules and Decoders with ModSecurity WAF Basics](https://medium.com/@alexxmacenas/wazuhs-rules-and-decoders-with-modsecurity-waf-5fb8f5aaa6a4)
