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
sidecar:

```sql
CREATE USER `alice@example.com`
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
GRANT mcp_reader TO `alice@example.com`;
```

ClickHouse grammar uses the bare `http` token — `http_authenticator` is
rejected with `SYNTAX_ERROR`. The `<http_authentication_servers>` server
name (`ch_jwt_verify`) is configurable via `ch.serverName` in
`values.yaml`.

## clickhouse-operator quirk: declare a `default` emptyDir volume

When splicing the sidecar into a `ClickHouseInstallation` CR's
`podTemplate` (clickhouse-operator-managed deployments), the operator
auto-injects `volumeMount{name: default, mountPath: /var/lib/clickhouse}`
on every container during StatefulSet rendering. The actual data PVC is
named after the volumeClaimTemplate (e.g. `default-1-1`), so the
injected mount references a volume that doesn't exist, and the pod fails
validation with:

```
spec.containers[N].volumeMounts[M].name: Not found: "default"
```

Workaround: declare an `emptyDir` volume named `default` in the
podTemplate's `volumes:` list (the sidecar never writes to it; it just
satisfies the operator's broken auto-injection):

```yaml
podTemplates:
- name: clickhouse-replica-1
  spec:
    containers:
      - name: clickhouse
        # ... existing CH container ...
    {{- include "ch-jwt-verify.container" . | nindent 6 }}
    volumes:
      - name: ch-jwt-verify-config
        configMap:
          name: {{ .Release.Name }}-ch-jwt-verify-config
      - name: default                # <-- satisfies the operator quirk
        emptyDir: {}
```

This is a clickhouse-operator behavior (observed on 26.1.x); the
sidecar itself has no `/var/lib/clickhouse` mount in its rendered spec
and never touches the directory.

## MCP-side configuration

Set the matching `oauth.audience` on the altinity-mcp Helm chart and keep
`oauth.mode: gating`. MCP rewrites the inbound Authorization header to
`Basic base64(email:JWT)`, ClickHouse extracts it, the sidecar verifies the
JWT, and ClickHouse impersonates the matching CH user for the duration of
the query.
