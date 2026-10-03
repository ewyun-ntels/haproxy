{{/* UD-001/015/016 v2-packaging-20261004: deterministic names and validation. */}}
{{- define "global-lb.fullname" -}}
{{- $name := default (printf "%s-%s" .Release.Name .Chart.Name) .Values.fullnameOverride -}}
{{- if gt (len $name) 48 -}}
{{- printf "%s-%s" ($name | trunc 39 | trimSuffix "-") ($name | sha256sum | trunc 8) -}}
{{- else -}}
{{- $name | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "global-lb.labels" -}}
app.kubernetes.io/name: haproxy-global-lb
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "global-lb.selector" -}}
app.kubernetes.io/name: haproxy-global-lb
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "global-lb.storeAddress" -}}
{{- if .Values.stateStore.enabled -}}
{{- printf "%s-store.%s.svc.%s:6379" (include "global-lb.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- else -}}
{{- required "stateStore.externalAddress is required when stateStore.enabled=false" .Values.stateStore.externalAddress -}}
{{- end -}}
{{- end -}}

{{- define "global-lb.validate" -}}
{{- if and .Values.stateStore.enabled .Values.stateStore.externalAddress -}}
{{- fail "stateStore.externalAddress must be empty when the bundled store is enabled" -}}
{{- end -}}
{{- $_ := include "global-lb.storeAddress" . -}}
{{- if gt (int .Values.replicaCount) (int .Values.globalLb.maxInstances) -}}
{{- fail "replicaCount exceeds globalLb.maxInstances (retained owner records also consume this limit)" -}}
{{- end -}}
{{- $names := dict -}}
{{- $ports := dict -}}
{{- $portNames := dict -}}
{{- $slots := 0 -}}
{{- range .Values.backends -}}
{{- if or (hasKey $names .name) (hasKey $ports (toString .port)) (hasKey $portNames .portName) -}}
{{- fail "backends require unique names, ports and portNames" -}}
{{- end -}}
{{- if eq (int .port) 8404 -}}
{{- fail "backend port 8404 is reserved for the internal health frontend" -}}
{{- end -}}
{{- if or (eq .portName "health") (eq .name "internal_health") -}}
{{- fail "health portName and internal_health backend name are reserved" -}}
{{- end -}}
{{- $slots = add $slots (int .slots) -}}
{{- $_ := set $names .name true -}}
{{- $_ := set $ports (toString .port) true -}}
{{- $_ := set $portNames .portName true -}}
{{- end -}}
{{- if gt $slots 4096 -}}
{{- fail "total backend server-template slots exceed the 4096 endpoint capture limit" -}}
{{- end -}}
{{- end -}}
