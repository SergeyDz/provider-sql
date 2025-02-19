{{- define "database.names" -}}
{{- $service := .service | replace "_" "-" -}}
{{- $suffix := .suffix -}}
{{- $dbName := printf "%s_%s" .service $suffix -}}
{{- $k8sName := printf "%s-%s" $service $suffix -}}
{{- dict "dbName" $dbName "k8sName" $k8sName | toJson -}}
{{- end -}}
