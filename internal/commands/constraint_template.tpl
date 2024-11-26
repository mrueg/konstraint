apiVersion: constraints.gatekeeper.sh/v1beta1
kind: {{ .Kind }}
metadata:
  {{- if .Annotations }}
  annotations: {{- range $key, $value := .Annotations }}
    {{ $key }}: {{ $value }}
  {{ end -}}
  {{ end -}}
  {{- if .Labels }}
  labels: {{- range $key, $value := .Labels }}
    {{ $key }}: {{ $value }}
  {{ end -}}
  {{ end -}}
  name: {{ .Name }}
spec:
  match:
    kinds:
  {{- if ne .Enforcement "deny" }}
  enforcementAction: {{ .Enforcement }}
  {{- end -}}
