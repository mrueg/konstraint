apiVersion: constraints.gatekeeper.sh/v1beta1
kind: {{ .Kind }}
metadata:
  {{ if .Annotations }}
  annotations: {{- toYaml .Annotations | nindent 4 }}
  {{ end -}}
  {{- if .Labels }}: 
  labels: {{ toYaml .Labels }}
  {{ end -}}
  name: {{ .Name }}
spec:
  match:
    kinds:
  {{ if ne .Enforcement "deny" }}
  enforcementAction: {{ .Enforcement }}
  {{- end -}}
  {{- if or .Parameters .AnnotationParameters }}
  {{- if .Parameters }}
  parameters: {{- range $key, $value := .Parameters }}
  {{ end -}} 
  {{ end -}}
  {{ end -}}