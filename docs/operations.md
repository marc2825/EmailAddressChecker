# Operations

## 1. Deployment gates

Do not enable service-active until all are true:

- static public IP;
- outbound port 25 confirmed;
- PTR configured;
- EHLO forward DNS aligned;
- SPF configured;
- sender mailbox monitored;
- abuse and postmaster mailboxes monitored;
- hosting terms reviewed;
- global kill switch tested;
- rate limits tested;
- private-network egress blocked;
- retention deletion tested;
- incident owner assigned.

## 2. Kill switches

At minimum:

- global active checks;
- one sender identity;
- one account/API key;
- one target domain;
- one target MX;
- automatic retries;
- raw evidence retention.

## 3. Alerting

Alert on:

- sudden rise in policy blocks;
- timeout or tarpit increase;
- authentication bypass attempts;
- rate-limit storage failure;
- queue growth;
- deletion job failure;
- sender IP blocklist appearance;
- remote abuse complaint;
- unsafe destination resolution attempt.

## 4. Runbooks

Before beta, create executable runbooks for:

- disable active probing;
- rotate compromised API key;
- disable sender identity;
- respond to abuse complaint;
- investigate false invalid;
- investigate destination SSRF alert;
- delete user data;
- restore queue/store;
- roll back ruleset.

## 5. Capacity

Remote etiquette dominates throughput. Increasing workers must not increase
per-domain or per-MX rates. Fair scheduling should prevent one domain from
occupying all worker capacity.
