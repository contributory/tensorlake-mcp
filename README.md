# Tensorlake MCP on Encore

Tensorlake MCP server deployed with Encore.go. It exposes the official MCP Streamable HTTP transport, uses Encore PostgreSQL for account/OAuth state, and supports OAuth 2.0 for ChatGPT MCP plugins/apps.

## Endpoints

- `POST /mcp` — MCP Streamable HTTP endpoint
- `GET /status` — health check
- `GET /.well-known/oauth-protected-resource` — RFC 9728 protected-resource metadata
- `GET /.well-known/oauth-protected-resource/mcp` — path-specific protected-resource metadata
- `GET /.well-known/oauth-authorization-server` — OAuth authorization-server metadata
- `GET|POST /oauth/authorize` — browser authorization flow and Tensorlake API-key entry
- `POST /oauth/token` — authorization-code and refresh-token grants
- `POST /oauth/register` — dynamic client registration fallback

## ChatGPT OAuth

The recommended authentication mode is OAuth 2.0 Authorization Code with PKCE S256.

When ChatGPT connects to `/mcp`, an unauthenticated request receives a `401` with a `WWW-Authenticate` challenge pointing at the protected-resource metadata. The authorization page asks the user for their Tensorlake API key. The key is validated against Tensorlake and stored in the Encore database for that account; it is never returned to the OAuth client.

The OAuth implementation supports:

- Authorization Code + PKCE S256
- refresh-token rotation
- `mcp` and `offline_access` scopes
- RFC 8707-style resource binding to `/mcp`
- RFC 9728 protected-resource metadata
- RFC 8414 authorization-server metadata
- ChatGPT Client ID Metadata Documents (CIMD)
- Dynamic Client Registration as a compatibility fallback
- hashed authorization codes, access tokens, and refresh tokens in the database

For backward compatibility, a raw Tensorlake API key can still be supplied as:

```http
Authorization: Bearer <TENSORLAKE_API_KEY>
```

Query-string API keys do not bypass OAuth. A raw `Authorization: Bearer` Tensorlake API key is the only legacy bypass; otherwise OAuth is required before MCP initialization or tool discovery.

## Sandbox selection

The service never creates a Tensorlake sandbox automatically and no longer uses `TENSORLAKE_SANDBOX_ID`.

The primary sandbox is stored per Tensorlake account in Encore PostgreSQL. Two MCP tools manage it:

- `list_sandboxes` — lists available Tensorlake sandboxes and marks the current primary sandbox.
- `set_sandbox` — validates an existing running sandbox and persists it as the primary sandbox.

These are administrative/configuration tools. Their MCP descriptions explicitly instruct the model **not** to call them routinely, before normal operations, or once per session. They should only be used when the user asks to inspect/switch sandboxes, when no primary sandbox exists, or when the current primary sandbox must be replaced.

Normal tools (`bash`, file tools, `grep`, `glob`, `upload`, `parse`) automatically resolve the saved primary sandbox from the database.

## Database

Encore provisions the `tensorlake` PostgreSQL database from migrations in `tensorlake/migrations`.

The database stores:

- Tensorlake account ID (SHA-256-derived tenant ID)
- Tensorlake API key
- selected primary sandbox ID
- OAuth dynamic clients
- one-time authorization codes
- OAuth sessions and token hashes

## Development

Use Encore to run or test the app because `encore.dev/storage/sqldb` resources require the Encore runtime:

```bash
encore test ./...
```

A local SQL database requires Docker when running through Encore.

## Deploy

The repository is linked to Encore app `tensorlake-mcp-http-kiwi`:

```bash
git push encore HEAD:refs/heads/main
```

Staging MCP endpoint:

```text
https://staging-tensorlake-mcp-http-kiwi.encr.app/mcp
```
