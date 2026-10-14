{{- /*
License exceptions: where the API gateway and the parsing workers read them
from. Shared by both deployments and the config ConfigMap so the mount, the
volume and EXCEPTIONS_* can never disagree.

Three mutually exclusive sources:
  custom (default)      rendered into <release>-license-exceptions
  existingConfigMap     a ConfigMap managed outside the chart
  source                an https:// URL or s3://bucket/key, fetched by the pods

ConfigMaps are mounted as a directory, never with subPath: subPath mounts do
not see ConfigMap updates, and the binaries re-read the file every
refreshInterval and re-check stored results when it changes.
*/ -}}

{{- define "bomhort.licenseExceptions.source" -}}
{{- $le := .Values.licenseExceptions -}}
{{- if $le.enabled }}{{ $le.source | default "" | trim }}{{ end -}}
{{- end -}}

{{- /* "true" when a ConfigMap is mounted into the pods. */ -}}
{{- define "bomhort.licenseExceptions.mounted" -}}
{{- if and .Values.licenseExceptions.enabled (not (include "bomhort.licenseExceptions.source" .)) }}true{{ end -}}
{{- end -}}

{{- /*
The file the binaries read. The chart's pre-0.8 default sat directly in
/data/config next to the subPath-mounted policy; a directory mount there would
hide it, so that exact value (still present after `helm upgrade
--reuse-values`) moves to the new default. The path is internal to the pods.
*/ -}}
{{- define "bomhort.licenseExceptions.file" -}}
{{- $path := .Values.licenseExceptions.mountPath | default "/data/config/license-exceptions/license-exceptions.json" -}}
{{- if eq $path "/data/config/license-exceptions.json" -}}
{{- $path = "/data/config/license-exceptions/license-exceptions.json" -}}
{{- end -}}
{{- $path -}}
{{- end -}}

{{- /* refreshInterval as a string; 0 is a value (no reloading), not unset. */ -}}
{{- define "bomhort.licenseExceptions.refreshInterval" -}}
{{- $v := .Values.licenseExceptions.refreshInterval -}}
{{- if or (kindIs "invalid" $v) (and (kindIs "string" $v) (eq $v "")) }}60s{{ else }}{{ $v | toString }}{{ end -}}
{{- end -}}

{{- define "bomhort.licenseExceptions.validate" -}}
{{- $le := .Values.licenseExceptions -}}
{{- if $le.enabled -}}
{{- $customSet := not (or (kindIs "invalid" $le.custom) (and (kindIs "string" $le.custom) (eq $le.custom ""))) -}}
{{- $source := include "bomhort.licenseExceptions.source" . -}}
{{- if and $le.existingConfigMap $customSet -}}
{{- fail "licenseExceptions.existingConfigMap and licenseExceptions.custom are mutually exclusive: set one of them, not both" -}}
{{- end -}}
{{- if and $source (or $le.existingConfigMap $customSet) -}}
{{- fail "licenseExceptions.source is mutually exclusive with licenseExceptions.custom and licenseExceptions.existingConfigMap: set one of them" -}}
{{- end -}}
{{- if and $source (not (or (hasPrefix "https://" $source) (hasPrefix "s3://" $source))) -}}
{{- fail (printf "licenseExceptions.source must be an https:// URL or s3://bucket/key (got %q)" $source) -}}
{{- end -}}
{{- $secret := $le.sourceTokenSecret | default dict -}}
{{- if and $secret.name (not $source) -}}
{{- fail "licenseExceptions.sourceTokenSecret is only used with licenseExceptions.source" -}}
{{- end -}}
{{- $interval := include "bomhort.licenseExceptions.refreshInterval" . -}}
{{- if not (regexMatch "^(0|([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+)$" $interval) -}}
{{- fail (printf "licenseExceptions.refreshInterval must be a duration such as 60s or 5m, or 0 to disable reloading (got %q)" $interval) -}}
{{- end -}}
{{- if include "bomhort.licenseExceptions.mounted" . -}}
{{- $dir := dir (include "bomhort.licenseExceptions.file" .) -}}
{{- if eq $dir "/" -}}
{{- fail "licenseExceptions.mountPath must be a file inside a directory of its own, e.g. /data/config/license-exceptions/license-exceptions.json" -}}
{{- end -}}
{{- $taken := list -}}
{{- if .Values.licensePolicy.enabled }}{{ $taken = append $taken (dir .Values.licensePolicy.mountPath) }}{{ end -}}
{{- $pg := .Values.projectGroups | default dict -}}
{{- if $pg.enabled }}{{ $taken = append $taken ($pg.mountDir | default "/data/config/project-groups" | trimSuffix "/") }}{{ end -}}
{{- $taken = append $taken (.Values.sbomSource.mountPath | trimSuffix "/") -}}
{{- range $taken -}}
{{- if or (eq . $dir) (hasPrefix (printf "%s/" $dir) .) -}}
{{- fail (printf "licenseExceptions.mountPath: its directory %s is mounted from the ConfigMap as a whole and collides with the mount at %s; give the exceptions a directory of their own, e.g. /data/config/license-exceptions/license-exceptions.json" $dir .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.licenseExceptions.volumeMount" -}}
{{- if include "bomhort.licenseExceptions.mounted" . }}
- name: license-exceptions
  mountPath: {{ dir (include "bomhort.licenseExceptions.file" .) }}
  readOnly: true
{{- end }}
{{- end -}}

{{- define "bomhort.licenseExceptions.volume" -}}
{{- if include "bomhort.licenseExceptions.mounted" . }}
{{- $le := .Values.licenseExceptions }}
- name: license-exceptions
  configMap:
    {{- if $le.existingConfigMap }}
    name: {{ $le.existingConfigMap }}
    items:
      - key: {{ $le.existingConfigMapKey | default "license-exceptions.json" }}
        path: {{ base (include "bomhort.licenseExceptions.file" .) }}
    {{- else }}
    name: {{ .Release.Name }}-license-exceptions
    {{- if ne (base (include "bomhort.licenseExceptions.file" .)) "license-exceptions.json" }}
    items:
      - key: license-exceptions.json
        path: {{ base (include "bomhort.licenseExceptions.file" .) }}
    {{- end }}
    {{- end }}
{{- end }}
{{- end -}}

{{- /* Container env entries; empty unless a token secret is configured. */ -}}
{{- define "bomhort.licenseExceptions.env" -}}
{{- $secret := .Values.licenseExceptions.sourceTokenSecret | default dict }}
{{- if and (include "bomhort.licenseExceptions.source" .) $secret.name }}
- name: EXCEPTIONS_SOURCE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secret.name }}
      key: {{ $secret.key | default "token" }}
{{- end }}
{{- end -}}
