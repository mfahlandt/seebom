---
title: "License Exceptions"
linkTitle: "License Exceptions"
type: docs
weight: 6
description: >
  Where the exception rules come from (Helm values, your own ConfigMap, an
  https or S3 source), how a change reaches running pods, and how a granted or
  revoked exception is applied to every SBOM already ingested.
---

License exceptions suppress specific license violations: a reviewed decision
that a package under a copyleft or unapproved license is acceptable for one
project or for all of them. This page covers where the rules come from, how a
change reaches running pods, how it is applied to SBOMs already ingested, and
the GitOps workflow. Which licenses count as copyleft in the first place is the
[license policy](/docs/deployment/#4-license-policy); how a package gets its
license is on the [License Resolution](/docs/license-resolution/) page. A
runnable example lives in
[`examples/license-exceptions/`](https://github.com/seebom-labs/BOMHort/tree/main/examples/license-exceptions).

## Sources

one source, which the API Gateway and the workers re-read every
`licenseExceptions.refreshInterval` (default `60s`):

| Source | Set | Use when |
|--------|-----|----------|
| Chart-rendered ConfigMap | `licenseExceptions.custom` (default) | the rules live in your Helm values |
| Your own ConfigMap | `licenseExceptions.existingConfigMap` | a second GitOps source / kustomize manages the reviewed file |
| URL or S3 object | `licenseExceptions.source` | the rules live outside the cluster, e.g. in a governance repository |

ConfigMaps are mounted as a directory (no `subPath`), so an edit reaches the
running pods without a restart. **Granting or revoking an exception applies to
every SBOM already ingested** — see [Retroactive application](#retroactive-application).

## Configuring rules in Helm values

`examples/license-exceptions/license-exceptions.example.json` structure to your
organization and approve only reviewed rules. Configure it with your normal values:

```bash
helm upgrade --install bomhort deploy/helm/bomhort -n bomhort \
  -f my-values.yaml --set-file licenseExceptions.custom=./my-exceptions.json
```

`licenseExceptions.custom` also accepts a YAML object. An explicit empty template is:

```yaml
licenseExceptions:
  enabled: true
  custom:
    version: "1.0.0"
    blanketExceptions: []
    exceptions: []
```

Use camelCase `blanketExceptions` and `package` (not `blanket_exceptions` or
`purl_prefix`). Both arrays are required. Only `status: "approved"` or
`"allowlisted"` activates a rule — every other value, including `denied`,
`not-eligible` and typos, leaves the entry inactive. Package names match exactly
or as complete slash-delimited suffixes; `project` is an exact SBOM document
name (omit it, use `"*"`, or phrase it as `all <qualifier> projects` for all
projects). A project scope never removes a rule's package restriction. Files
exported from a published exception registry load as-is: the provenance fields
`results`, `issueUrl` and `packageUrl` are accepted and kept as audit metadata.
Audit fields such as `scope` and dates are informational, not automatically
enforced conditions.

Empty lists are authoritative and never load old approvals from the SBOM directory.
Fallback is allowed only when the primary file is absent. Invalid configuration
stops the worker and returns HTTP 500 from exception-related API endpoints.
Keep the ConfigMap enabled with empty lists to disable approvals; disabling the
mount alone does not disable the legacy SBOM-directory fallback.

A change needs neither a restart nor a re-scan: the pods reload the rules and
the stored results of existing SBOMs are re-checked automatically. Changes to
the [license policy](/docs/deployment/#4-license-policy) — which licenses count as copyleft — are
different and still need a re-scan.

## Retroactive application

When the workers see a new version of the rules (compared by SHA-256 digest),
one of them enqueues a `license_recheck` job. It re-evaluates every stored
`license_compliance` row under the new rules and rewrites only the rows whose
outcome changed: a granted exception moves packages from *non-compliant* to
*exempted*, a revoked one moves them back. No SBOM is re-parsed and no
registry or OSV lookup is repeated.

- The job waits `2 × refreshInterval` (plus 90 s for a mounted ConfigMap, the
  kubelet's sync delay) before it runs, so every replica has reloaded first and
  SBOMs ingested in between are already checked against the new rules.
- Replicas coordinate through the queue: several workers seeing the same change
  enqueue one job. Reverting to an earlier version is a change like any other.
- A recheck runs only on a worker that has loaded the rules it was queued for;
  a worker still on older rules defers it. A failed recheck, or one whose worker
  died mid-run (still `processing` after an hour), is queued again within one
  `refreshInterval`. The worker log reports
  `License recheck: N stored results checked, M updated`.
- With `refreshInterval: 0` the rules are read once at startup; a restart then
  re-checks stored results against them.

## Exceptions from outside the cluster: `source`

```yaml
licenseExceptions:
  source: https://raw.githubusercontent.com/your-org/governance/main/license-exceptions.json
  sourceTokenSecret:          # optional, for a private repository
    name: governance-token
    key: token                # sent as "Authorization: Bearer <token>"
  refreshInterval: 5m
```

`source` also accepts `s3://bucket/key`, read with the [S3 credentials](/docs/deployment/#option-a-s3-buckets-default-recommended)
the chart already passes to the pods. It is mutually exclusive with `custom` and
`existingConfigMap`, and nothing is mounted. Only `https://` is accepted; responses
over 10 MiB are rejected, and the URL is never logged (it may carry a signed
query string).

- **Unreachable source:** the pods keep the last rules that loaded and retry.
  Workers do not start until the first load succeeds; the API gateway starts and
  answers exception-related endpoints with HTTP 503 until then.
- **Invalid document:** treated like an invalid file — the API returns HTTP 500
  for exception-related endpoints, the workers keep the last good rules and log
  the error, and nothing is re-checked until a valid document is published.
- **Missing document (404 / no such key):** an error, never "no exceptions":
  approvals do not silently disappear because a path moved.
- An `s3://` rules object may live in a bucket the ingestion watcher scans: the
  watcher only ingests keys ending in an SBOM or VEX suffix (`.spdx.json`,
  `_spdx.json`, `.vex.json`, `.openvex.json`), so `license-exceptions.json` is
  skipped. Do not give the rules object one of those suffixes.

For upgrades, remove `seedJob.cncfExceptionsURL` (also from retained Helm values)
and supply reviewed rules explicitly. `"All CNCF Projects"` is now a literal
project name, not a global approval. The default license classification policy
is unchanged.

## Argo CD (GitOps)

License exception updates also work when Argo CD renders the chart with
`helm template`: nothing depends on running `helm upgrade` or on a Helm
upgrade hook.

Keep exceptions in your GitOps repository, either in a Helm values file referenced
by `spec.source.helm.valueFiles` or directly in `spec.source.helm.valuesObject`.
The following is a **fragment to merge into your existing Application**, not a
complete deployment manifest. For multi-source Applications, use the Helm chart
entry under `spec.sources[]` instead of `spec.source`.

```yaml
spec:
  source:
    helm:
      valuesObject:
        licenseExceptions:
          enabled: true
          custom:
            version: "1.0.0"
            blanketExceptions: []
            exceptions:
              - id: example-review-required
                package: example.org/your-team/your-library
                license: MPL-2.0
                project: your-exact-sbom-document-name
                status: pending
                approvedDate: ""
                comment: "Example only; requires organization approval."
```

This example grants **no approval**. Replace the placeholders, review the rule,
then explicitly set `status: approved` only after approval. To remove all
approvals, keep `enabled: true` and set both arrays to `[]`.

If your Argo CD Application CRD does not support `valuesObject`, use a committed
values file or the equivalent YAML in `helm.values`. Do not rely on a workstation's
local `--set-file` invocation: Argo must receive the configuration through its own
Git-backed Helm inputs. Avoid defining the same exceptions in multiple layers;
`valuesObject` overrides `valueFiles`, and Helm `parameters` override both.

**What happens on a change:**

1. Commit the reviewed values and let Argo refresh the desired manifests.
2. Only the rendered ConfigMap data changes; the Deployments stay as they are.
3. At the next sync (manual or automated according to your Application policy),
   Argo applies the ConfigMap. The kubelet updates the mounted file, the pods
   reload it, and stored results are [re-checked](#retroactive-application).
   No restart and no re-scan is needed.

**Deployment checklist:**

- Point Argo at a chart revision **and API/worker image versions containing these
  fixes**. Updating only the chart does not update the matching/loading behavior
  in older binaries. Local, unpushed changes are not available to Argo.
- Remove `seedJob.cncfExceptionsURL` from all GitOps values and parameter overrides;
  the chart rejects this retired option with a migration hint.
- For an exception-only change, the Argo diff shows the ConfigMap only.
- Verify the configured rules through `GET /api/v1/license-exceptions` or the
  UI's **Configured Exceptions** tab, and the worker log for the
  `License recheck` line once the recheck has run.

Do not edit the managed ConfigMap with `kubectl edit` as a normal configuration
workflow: the next Argo sync or self-heal can overwrite the change. Git is the
source of truth for the exceptions and their review history.

### Reviewed rules from their own source: `existingConfigMap`

Inlining a large reviewed file — the CNCF foundation exceptions are ~180 KB —
into an Application turns every upstream refresh into a huge diff in an
unrelated manifest. Instead, let a second source manage the ConfigMap and point
the chart at it:

```yaml
spec:
  sources:
    - repoURL: ghcr.io/seebom-labs/bomhort/charts
      chart: bomhort
      targetRevision: 0.8.0
      helm:
        valuesObject:
          licenseExceptions:
            existingConfigMap: license-exceptions   # mutually exclusive with custom
            # existingConfigMapKey: license-exceptions.json   # default
          # licensePolicy:
          #   existingConfigMap: license-policy             # same mechanism
    - repoURL: https://github.com/your-org/compliance.git
      targetRevision: main
      path: bomhort/license-exceptions      # contains the kustomization below
```

```yaml
# bomhort/license-exceptions/kustomization.yaml
configMapGenerator:
  - name: license-exceptions
    files:
      - license-exceptions.json=exceptions.json   # the reviewed file, verbatim
    options:
      disableNameSuffixHash: true
```

The chart then renders no exceptions ConfigMap and mounts the named one, mapping
`existingConfigMapKey` to `license-exceptions.json`. Setting both `custom` and
`existingConfigMap` fails the render. If the referenced ConfigMap does not
exist, the pods do not start: running without the reviewed rules would be worse.

Edits to that ConfigMap reach the running pods like edits to the chart's own:
no restart, no re-scan. Keep `disableNameSuffixHash: true` as above — a
generator hash suffix would give every revision a new name, and changing the
name in the chart values rolls the pods instead of reloading.

If the reviewed file lives in a repository Argo does not manage, skip the
ConfigMap entirely and point [`source`](#exceptions-from-outside-the-cluster-source)
at it.

---
