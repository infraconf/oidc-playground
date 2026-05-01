# Options

This document explains the optional `options` parameter for the `/authorize` request.

## Full ID Token

Option key: `full-id-token`

Effect:
Without this option, the ID token only contains the base OIDC claims plus `c_hash` and `at_hash`.
With this option, the ID token also includes the user claims that would normally appear in the UserInfo response, based on the requested scopes.

Example request:

```text
/authorize?response_type=code&client_id=demo-client&redirect_uri=https://client.example/callback&scope=openid profile email groups&options=full-id-token
```

Example result without `full-id-token`:

```json
{
  "iss": "https://issuer.example",
  "sub": "user:alice",
  "aud": "demo-client",
  "exp": 1712345678,
  "iat": 1712342078,
  "auth_time": 1712342078,
  "c_hash": "...",
  "at_hash": "...",
  "nonce": "..."
}
```

Example result with `full-id-token`:

```json
{
  "iss": "https://issuer.example",
  "sub": "user:alice",
  "aud": "demo-client",
  "exp": 1712345678,
  "iat": 1712342078,
  "auth_time": 1712342078,
  "preferred_username": "alice",
  "name": "Alice Example",
  "given_name": "Alice Example",
  "nickname": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "groups": [
    "developers",
    "admins"
  ],
  "c_hash": "...",
  "at_hash": "...",
  "nonce": "..."
}
```
