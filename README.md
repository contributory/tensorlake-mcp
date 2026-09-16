# Tensorlake MCP on Encore

Encore.go deployment wrapper for the SIXT/Tensorlake MCP server.

## Endpoints

- `POST /mcp` — MCP Streamable HTTP endpoint (stateless, JSON response mode)
- `GET /healthz` — health check

`/mcp` requires `Authorization: Bearer <token>`.

## Encore secrets

The service declares two Encore secrets:

- `TensorlakeAPIKey` — Tensorlake API key
- `MCPBearerToken` — bearer token required by MCP clients

Set them for the target environment before deployment.

## Local validation

```bash
go test ./...
encore test ./...
```

Both test suites validate the adapter and Encore application model. The MCP initialize handshake is covered by `tensorlake/encore_api_test.go`.

## Deploy to Encore Cloud

Link the repository to an Encore Cloud app, configure both secrets for the target environment, then deploy using Encore's Git integration (`git push encore`) or the Encore deploy command.

After deployment the MCP URL is:

```text
https://<your-encore-domain>/mcp
```

Configure clients with the HTTP endpoint and an Authorization bearer header.

## Design notes

The upstream server originally uses stdio. This wrapper keeps the Tensorlake tools unchanged and replaces the process entrypoint with `mcp.NewStreamableHTTPHandler`. The MCP transport is stateless, but the upstream Tensorlake server keeps the active sandbox ID in process-local state. Run this adapter as a single service instance unless you add a shared sandbox-session store. Use separate deployments/tokens when hard workspace isolation is required.
