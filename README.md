# Tensorlake MCP on Encore

Encore.go deployment wrapper for the SIXT/Tensorlake MCP server.

## Endpoints

- `POST /mcp` — MCP Streamable HTTP endpoint (stateless, JSON response mode)
- `GET /status` — health check

## Authentication / Tensorlake API key

The Tensorlake API key is supplied by each MCP client request. The service does not require a server-side Tensorlake API key secret.

Preferred:

```http
Authorization: Bearer <TENSORLAKE_API_KEY>
```

Query parameter fallback:

```text
/mcp?tensorlake_api_key=<TENSORLAKE_API_KEY>
```

The shorter alias `api_key` is also accepted:

```text
/mcp?api_key=<TENSORLAKE_API_KEY>
```

If both a Bearer header and query parameter are present, the Bearer value wins.

Bearer is recommended because query-string credentials may be visible to proxies, access logs, browser history, and observability systems before the application can redact them.

## Tenant isolation

Each distinct Tensorlake API key gets its own Tensorlake client, sandbox state, persisted sandbox ID, and background-process namespace. The in-memory tenant map is keyed by SHA-256 of the API key rather than the raw credential.

The MCP transport itself remains stateless. The active Tensorlake sandbox is process-local plus a temporary persisted sandbox-ID file, so horizontally scaling the service still requires a shared session store if requests for one API key can land on different instances.

## Sandbox configuration

The service never creates a Tensorlake sandbox automatically. Configure the existing running sandbox through the Encore secret `TENSORLAKE_SANDBOX_ID`:

```bash
encore secret set --env staging TENSORLAKE_SANDBOX_ID
```

Set the secret value to the sandbox ID you want the MCP service to reuse. Encore injects this value into the Go `secrets` struct at runtime.
```bash
encore test ./...
```

The adapter tests cover missing credentials, Bearer credentials, both supported query parameters, and Bearer-over-query precedence.

## Deploy to Encore Cloud

The repository is linked to Encore app `tensorlake-mcp-http-kiwi`. Push the branch to Encore to deploy:

```bash
git push encore HEAD:refs/heads/main
```

Staging endpoint:

```text
https://staging-tensorlake-mcp-http-kiwi.encr.app/mcp
```
