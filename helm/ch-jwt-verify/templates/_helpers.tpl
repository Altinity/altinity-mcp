{{/*
ch-jwt-verify Helm helpers.

Most operators pull the sidecar container fragment via:
  containers:
    - <existing ClickHouse container>
    {{- include "ch-jwt-verify.container" . | nindent 4 }}

This lets the sidecar share lifecycle with the CH pod (the only place its
loopback trust model holds).
*/}}

{{- define "ch-jwt-verify.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ch-jwt-verify.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "ch-jwt-verify.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "ch-jwt-verify.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Reusable container fragment to splice into the CH StatefulSet/Deployment.

When running under clickhouse-operator, the operator auto-injects
volumeMount{name: default, mountPath: /var/lib/clickhouse} on every
container in the podTemplate. The actual data PVC volume is named after
the volumeClaimTemplate (e.g. default-1-1), so the injected mount fails
validation. Workaround: declare an emptyDir volume named "default" in
the podTemplate's volumes list (see README.md § operator quirk).
*/}}
{{- define "ch-jwt-verify.container" -}}
- name: ch-jwt-verify
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
    - --config=/etc/ch-jwt-verify/config.yaml
  env:
    - name: CH_JWT_VERIFY_LOG_LEVEL
      value: info
  volumeMounts:
    - name: ch-jwt-verify-config
      mountPath: /etc/ch-jwt-verify
      readOnly: true
  {{- if .Values.listen.tcp }}
  ports:
    - name: verify
      containerPort: {{ regexFind "[0-9]+$" .Values.listen.tcp | int }}
      protocol: TCP
  readinessProbe:
    httpGet:
      path: /healthz
      port: {{ regexFind "[0-9]+$" .Values.listen.tcp | int }}
    initialDelaySeconds: 1
    periodSeconds: 5
  livenessProbe:
    httpGet:
      path: /healthz
      port: {{ regexFind "[0-9]+$" .Values.listen.tcp | int }}
    initialDelaySeconds: 10
    periodSeconds: 30
  {{- end }}
  resources: {{- toYaml .Values.resources | nindent 4 }}
{{- end }}
