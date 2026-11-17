# Test TLS material

Everything here is a test fixture. None of it is secret, production code never uses it, and none of it may become a production trust anchor.

| File | What it is |
|---|---|
| `ca.crt`, `ca.key` | A throwaway CA. The client trusts it only because a test passes it as an extra anchor. |
| `server.crt`, `server.key` | `mx.test.example`, signed by that CA. The success path. |
| `wrong-name.crt`, `wrong-name.key` | `other.test.example`, signed by that CA. Proves hostname verification is on: the chain is valid and the handshake must still fail. |
| `untrusted.crt`, `untrusted.key` | `mx.test.example`, self-signed. Proves certificate verification is on. |

The keys are ECDSA P-256 and the certificates expire in 2126, so no test starts failing on a date. The CA certificate has critical `keyCertSign` and `cRLSign` key usage, which the strict X.509 validation in Python 3.13 and later requires. Production certificate and hostname verification is never relaxed for a test.

## Why these are committed rather than generated

Generating a certificate needs `cryptography`, which this project does not depend on, or the `openssl` binary, which a CI image may lack. Committed fixtures keep the TLS tests deterministic and free of extra dependencies.

## How the separation is kept

`build_client_context()` always sets `check_hostname = True` and `verify_mode = CERT_REQUIRED`, with no parameter to turn either off. A caller may add an extra trust anchor and nothing else; that is the only seam these fixtures use, so the worst misuse trusts one more CA. `tests/unit/adapters/test_tls_context.py` asserts that verification cannot be disabled.

## Regenerating

```bash
cd tests/fixtures/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.crt -days 36500 -subj "/CN=emailcheck test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout server.key -out server.csr -subj "/CN=mx.test.example"
printf "subjectAltName=DNS:mx.test.example\nbasicConstraints=CA:FALSE\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 36500 -extfile ext.cnf
```

`wrong-name.*` is the same with `CN=other.test.example`, and `untrusted.*` is a
self-signed `mx.test.example`.
