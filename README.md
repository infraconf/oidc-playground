# OIDC Playground

OIDC Playground is a small OpenID Connect test server for local development, demos, and protocol exploration. It provides a compact environment for trying common OIDC flows and inspecting how clients interact with an identity provider.

## Quickstart

1. Create a JSON config file for the server, clients, and demo users.
2. Start the container and mount the config into `/etc/idp/config.json`.
3. Configure your OIDC client to use the local issuer and one of the redirect URIs registered in the config.

Example:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/example_config.json:/etc/idp/config.json:ro" \
  ghcr.io/infraconf/oidc-playground:latest
```

Then open:

- Discovery document: `http://localhost:8080/.well-known/openid-configuration`
- Authorization flow entry: `http://localhost:8080/connect/authorize`

If you keep your config somewhere else, set `IDP_CONFIG_PATH` and mount that path into the container:

```bash
docker run --rm \
  -p 8080:8080 \
  -e IDP_CONFIG_PATH=/config/oidc-playground.json \
  -v "$(pwd)/oidc-playground.json:/config/oidc-playground.json:ro" \
  ghcr.io/infraconf/oidc-playground:latest
```

## Docker Compose

```yaml
services:
  oidc-playground:
    image: ghcr.io/infraconf/oidc-playground:latest
    ports:
      - "8080:8080"
    volumes:
      - ./example_config.json:/etc/idp/config.json:ro
```

Start it with:

```bash
docker compose up
```

## Configuration

The application reads a single JSON file with three top-level sections:

```json
{
  "server": {},
  "clients": [],
  "users": []
}
```

The default config path inside the container is `/etc/idp/config.json`. You can override it with `IDP_CONFIG_PATH`.

### `server`

The `server` section controls issuer metadata and token signing.

```json
{
  "server": {
    "issuer": "http://localhost:8080",
    "signing_key": "BASE64_ENCODED_RSA_PRIVATE_KEY"
  }
}
```

- `issuer`: Optional fixed issuer URL. If this field is empty, the server derives the issuer from the incoming request and uses that value in discovery metadata and issued tokens.
- `signing_key`: Optional base64-encoded RSA private key in DER format. PKCS#1 and PKCS#8 are supported. If omitted, the server generates a new RSA key at startup. That is convenient for local testing, but tokens will change across container restarts and previously issued tokens will no longer validate against a new key.

### `clients`

The `clients` array defines which OAuth/OIDC clients may use the playground.

```json
{
  "clients": [
    {
      "client_id": "demo-client",
      "client_secret": "demo-secret",
      "redirect_uris": [
        "http://localhost:8080/callback",
        "http://localhost:3000/auth/callback"
      ]
    }
  ]
}
```

- `client_id`: Required. Must match the `client_id` sent to `/connect/authorize` and `/connect/token`.
- `client_secret`: Required. Used for token and revocation endpoint authentication. The server supports `client_secret_basic` and `client_secret_post`.
- `redirect_uris`: Required list of exact allowed redirect URIs. Only `http` and `https` are accepted. The authorization request must use one of these values exactly.

You can define multiple clients. Each client can have its own callback URLs, which makes the playground usable for several local applications at the same time.

### `users`

The `users` array defines the selectable identities shown during authorization.

```json
{
  "users": [
    {
      "id": "john",
      "name": "John Doe",
      "description": "Admin user",
      "claims": {
        "email": "john.doe@example.com",
        "groups": ["admin", "platform"]
      },
      "custom_claims": {
        "profile": {
          "department": "engineering"
        },
        "app": {
          "tenant": "demo",
          "permissions": ["read", "write"]
        }
      }
    }
  ]
}
```

- `id`: Required internal user identifier. It is also used as the basis for the token subject.
- `name`: Optional display name. Used in the authorization UI and for profile-style claims.
- `description`: Optional short label shown in the authorization UI.
- `claims.email`: Optional email value. Included when the client requests the `email` scope.
- `claims.groups`: Optional group list. Included when the client requests the `groups` scope.
- `custom_claims`: Optional scope-to-claim mapping. Each entry key is treated like a scope name, and its object is merged into the resulting ID token or UserInfo response when that scope is present.

`custom_claims` is the main extension point in the config. It lets you model application-specific scopes without changing code. For example:

- Put claims under `profile` if you want them when the client asks for `profile`.
- Put claims under `app` if your client requests a custom `app` scope.
- Put different claim sets under different scope names to simulate permission-dependent token contents.

### Scope Behavior

The server advertises the scopes `openid`, `profile`, `email`, and `groups`.

- `openid` enables ID token issuance.
- `profile` adds `preferred_username`, `name`, `given_name`, and `nickname`.
- `email` adds `email` and `email_verified`.
- `groups` adds `groups`.
- Any additional scope can still be useful if you map it in `custom_claims`, because matching entries are added to the token payload and UserInfo response.

## Operational Notes

- The authorization endpoint currently supports only `response_type=code`.
- PKCE is supported with `code_challenge_method=S256`.
- The container listens on `:8080`.
- If no users are configured, interactive authorization cannot complete.

## License

This project is available under the MIT License. See [`LICENSE`](LICENSE) for details.
