# altinity-mcp

![Version: 1.0.6](https://img.shields.io/badge/Version-1.0.6-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.6](https://img.shields.io/badge/AppVersion-1.0.6-informational?style=flat-square)

A Helm chart for Altinity MCP Server

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity settings for pod assignment |
| autoscaling.enabled | bool | `false` | Enable autoscaling |
| autoscaling.maxReplicas | int | `100` | Maximum number of replicas |
| autoscaling.minReplicas | int | `1` | Minimum number of replicas |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| config.clickhouse.database | string | `"default"` |  |
| config.clickhouse.host | string | `"localhost"` |  |
| config.clickhouse.limit | int | `1000` |  |
| config.clickhouse.max_execution_time | int | `30` |  |
| config.clickhouse.password | string | `""` |  |
| config.clickhouse.port | int | `8123` |  |
| config.clickhouse.protocol | string | `"http"` |  |
| config.clickhouse.read_only | bool | `false` |  |
| config.clickhouse.tls.ca_cert | string | `""` |  |
| config.clickhouse.tls.client_cert | string | `""` |  |
| config.clickhouse.tls.client_key | string | `""` |  |
| config.clickhouse.tls.enabled | bool | `false` |  |
| config.clickhouse.tls.insecure_skip_verify | bool | `false` |  |
| config.clickhouse.username | string | `"default"` |  |
| config.logging.level | string | `"info"` |  |
| config.server.address | string | `"0.0.0.0"` |  |
| config.server.dynamic_tools | list | `[]` | Dynamic tools generated from ClickHouse views |
| config.server.oauth.audience | string | `""` | Expected audience claim in the token |
| config.server.oauth.auth_url | string | `""` | OAuth authorization endpoint URL |
| config.server.oauth.claims_to_headers | object | `{}` | Map OAuth token claims to ClickHouse HTTP headers |
| config.server.oauth.clickhouse_header_name | string | `""` | Header name for forwarding OAuth token to ClickHouse |
| config.server.oauth.client_id | string | `""` | OAuth client ID |
| config.server.oauth.client_secret | string | `""` | OAuth client secret |
| config.server.oauth.enabled | bool | `false` | Enable OAuth 2.0 authentication |
| config.server.oauth.issuer | string | `""` | OAuth token issuer URL for validation |
| config.server.oauth.jwks_url | string | `""` | URL to fetch JSON Web Key Set for token validation |
| config.server.oauth.required_scopes | list | `[]` | Required scopes for access (token must have all of these) |
| config.server.oauth.scopes | list | `[]` | OAuth scopes to request |
| config.server.oauth.token_url | string | `""` | OAuth token endpoint URL |
| config.server.jwe.enabled | bool | `false` |  |
| config.server.jwe.jwe_secret_key | string | `""` |  |
| config.server.jwe.jwt_secret_key | string | `""` |  |
| config.server.jwe.token_param | string | `"token"` |  |
| config.server.port | int | `8080` |  |
| config.server.tls.ca_cert | string | `""` |  |
| config.server.tls.cert_file | string | `""` |  |
| config.server.tls.enabled | bool | `false` |  |
| config.server.tls.key_file | string | `""` |  |
| config.server.transport | string | `"http"` |  |
| env | list | `[]` | Environment variables for the main container (e.g. `CLICKHOUSE_PASSWORD` via `valueFrom.secretKeyRef`) |
| fullnameOverride | string | `""` | Override the full name of the chart |
| image.pullPolicy | string | `"IfNotPresent"` | Container image pull policy |
| image.repository | string | `"ghcr.io/altinity/altinity-mcp"` | Container image repository |
| image.tag | string | `""` | Overrides the image tag whose default is the chart appVersion. |
| imagePullSecrets | list | `[]` | Pull secrets for private images |
| ingress.annotations | object | `{}` | Ingress annotations |
| ingress.className | string | `""` | Ingress class name |
| ingress.enabled | bool | `false` | Enable ingress controller resource |
| ingress.hosts[0] | object | `{"host":"chart-example.local","paths":[{"path":"/","pathType":"Prefix"}]}` | Ingress host |
| ingress.hosts[0].paths[0] | object | `{"path":"/","pathType":"Prefix"}` | Ingress path |
| ingress.hosts[0].paths[0].pathType | string | `"Prefix"` | Ingress path type |
| ingress.tls | list | `[]` | Ingress TLS configuration |
| nameOverride | string | `""` | Override the name of the chart |
| nodeSelector | object | `{}` | Node labels for pod assignment |
| podAnnotations | object | `{}` | Pod annotations |
| podSecurityContext | object | `{}` | Pod security context |
| probes | object | `{"liveness":{"initialDelaySeconds":7,"path":"/livez","periodSeconds":30},"readiness":{"initialDelaySeconds":7,"path":"/health","periodSeconds":30}}` | Probe configuration |
| probes.liveness.initialDelaySeconds | int | `7` | Initial delay before liveness probe starts |
| probes.liveness.path | string | `"/livez"` | Path for the liveness probe |
| probes.liveness.periodSeconds | int | `30` | How often to perform the liveness probe |
| probes.readiness.initialDelaySeconds | int | `7` | Initial delay before readiness probe starts |
| probes.readiness.path | string | `"/health"` | Path for the readiness probe |
| probes.readiness.periodSeconds | int | `30` | How often to perform the readiness probe |
| replicaCount | int | `1` | Number of replicas to deploy |
| resources | object | `{}` | Container resource requests and limits |
| securityContext | object | `{}` | Container security context |
| service.annotations | object | `{}` | Service annotations |
| service.port | int | `8080` | Service port |
| service.sessionAffinity | string | `nil` | Session affinity type. Set to "ClientIP" to enable sticky sessions. |
| service.sessionAffinityConfig | object | `nil` | Session affinity configuration (only used when sessionAffinity is set) |
| service.type | string | `"ClusterIP"` | Service type |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| tolerations | list | `[]` | Toleration labels for pod assignment |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
