# ch-jwt-verify

A Helm chart that ships the ClickHouse-side JWT verifier sidecar bundled with
this repo (`cmd/ch-jwt-verify/`).

The chart does **not** render a Deployment or StatefulSet. The sidecar must
live in the same pod as ClickHouse so that the loopback trust model holds
(zero network exposure beyond the pod). What the chart renders instead:

- a `ConfigMap` with the sidecar's YAML config (`<release>-ch-jwt-verify-config`)
- a `ConfigMap` with the CH-side `http_authentication_servers` XML snippet
  (`<release>-ch-jwt-verify-ch-config`) for `config.d/`
- a reusable container fragment in `_helpers.tpl` you reference from your
  ClickHouse chart's pod spec

## Wiring

In your ClickHouse `StatefulSet` (typically via the
[clickhouse-operator](https://github.com/Altinity/clickhouse-operator) podTemplate):

```yaml
containers:
  - name: clickhouse
    # ... your existing container spec ...
    volumeMounts:
      - name: ch-jwt-verify-ch-config
        mountPath: /etc/clickhouse-server/config.d/http_authentication.xml
        subPath: http_authentication.xml
  {{- include "ch-jwt-verify.container" . | nindent 2 }}
volumes:
  - name: ch-jwt-verify-config
    configMap:
      name: {{ .Release.Name }}-ch-jwt-verify-config
  - name: ch-jwt-verify-ch-config
    configMap:
      name: {{ .Release.Name }}-ch-jwt-verify-ch-config
```

## Per-user binding

After deploying, provision per-user CH accounts that delegate to the
`http_authenticator`:

```sql
CREATE USER "alice@example.com"
  IDENTIFIED WITH http_authenticator SERVER 'ch_jwt_verify';
GRANT mcp_reader TO "alice@example.com";
```

The CH `<http_authentication_servers>` server name (`ch_jwt_verify`) is
configurable via `ch.serverName` in `values.yaml`.

## MCP-side configuration

Set the matching `oauth.audience` on the altinity-mcp Helm chart and keep
`oauth.mode: gating`. MCP rewrites the inbound Authorization header to
`Basic base64(email:JWT)`, ClickHouse extracts it, the sidecar verifies the
JWT, and ClickHouse impersonates the matching CH user for the duration of
the query.
