# Privacy and data handling

## 1. Data categories

- submitted address;
- normalized domain;
- target HMAC;
- account and API-key identifiers;
- DNS evidence;
- SMTP structured evidence;
- bounded raw diagnostic;
- timestamps and latency;
- abuse features.

## 2. Data minimization

Default behavior:

- process the plaintext address only for the active job;
- redact in ordinary logs;
- use HMAC for correlation;
- aggregate metrics by domain/MX and reason;
- do not keep raw protocol text unless debugging retention is explicitly enabled.

## 3. Retention defaults

- plaintext request: 24 hours;
- encrypted raw SMTP diagnostic: 24 hours;
- result history: disabled by default or 30 days when explicitly enabled;
- HMAC and aggregate audit data: policy-defined, with deletion support;
- account and billing records: separate policy.

## 4. Redaction

Examples:

```text
alice@example.com → a***@example.com
a@example.com     → *@example.com
```

Do not rely on redaction as anonymization. Domain and local-part patterns can
remain identifying.

## 5. HMAC

Use a secret key distinct from encryption keys.

```text
HMAC-SHA-256(key, canonical_input_version || normalized_target)
```

Store the canonicalization version. A plain unsalted hash is not sufficient
because addresses are guessable.

## 6. Access

- raw evidence administrator-only;
- account users see their safe normalized results;
- support access is logged;
- secret material is never returned;
- API errors do not contain raw remote replies.

## 7. Deletion

Implement and test:

- scheduled expiry;
- account-requested deletion;
- API-key revocation;
- deletion of plaintext separate from aggregate metrics;
- deletion failure alerting.

Obtain legal review before commercial or cross-border production use.
