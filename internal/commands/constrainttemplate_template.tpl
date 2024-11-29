apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: {{ .Name }}
spec:
  crd:
    spec:
      names:
        kind: {{ .Kind }}
      {{- if or .Parameters .AnnotationParameters }}
      validation:
        openAPIV3Schema:
          properties:
            {{- if .Parameters }}
            {{ toYaml .GetOpenAPISchemaProperties }}
            {{ else -}}
            {{ .AnnotationParameters | toJson | fromJson | toYaml | nindent 10 }}
            {{ end -}}
      {{- end }}
  targets:
  - libs: {{- range .Dependencies }}
    - |- {{- . | nindent 6 -}}
    {{ end }}
    rego: |- {{- .Source | nindent 6 }}
    target: admission.k8s.gatekeeper.sh