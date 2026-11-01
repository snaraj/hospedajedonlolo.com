{{- define "hospedajedonlolo-com.name" -}}
hospedajedonlolo-com
{{- end -}}

{{/*
app.kubernetes.io/version is derived from .Chart.AppVersion, so no override can
make the label disagree with the chart that rendered it. It is a label and
never a selector key: selectors are immutable on a live Deployment.
*/}}
{{- define "hospedajedonlolo-com.labels" -}}
app.kubernetes.io/name: {{ include "hospedajedonlolo-com.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
