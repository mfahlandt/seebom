# CNCF-inspired theme

A `custom-theme.css` + `ui-config.json` pair that restyles BOMHort with the
public [CNCF colour palette](https://www.cncf.io/brand-guidelines/)
(CNCF Blue `#0086FF`, Black, Turquoise `#93EAFF`, Pink `#D62293`, Stone
`#E5E5E5`) and the Clarity City font stack, similar in feel to
[contribute.cncf.io](https://contribute.cncf.io/contributors/).

Light navbar (white, Stone rule, CNCF Blue active link), CNCF Blue accent,
Pink for critical findings, and the CNCF wordmark (`brand/cncf-logo.svg`,
the unmodified primary logo) in place of the mascot via `brandLogo`.

```bash
# Docker Compose
CUSTOM_THEME=./examples/themes/cncf/custom-theme.css \
UI_CONFIG=./examples/themes/cncf/ui-config.json \
BRAND_ASSETS=./examples/themes/cncf/brand \
make dev
```

```bash
# Kubernetes – mount via ConfigMap (see Helm values ui.customTheme / ui.siteConfig)
kubectl create configmap bomhort-theme --from-file=custom-theme.css=examples/themes/cncf/custom-theme.css
```

**Trademark note.** The [brand guidelines](https://www.cncf.io/brand-guidelines/)
require the logo to be used unmodified and ask that websites check in with
`brand@linuxfoundation.org` before using it; "Member of CNCF" or a CNCF
project's own deployment is the intended case. Keep the attribution in the
disclaimer, or drop `brandLogo` from `ui-config.json` to run with colours only.
