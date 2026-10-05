# CNCF-inspired theme

A `custom-theme.css` + `ui-config.json` pair that restyles BOMHort with the
public [CNCF colour palette](https://www.cncf.io/brand-guidelines/)
(CNCF Blue `#0086FF`, Black, Turquoise `#93EAFF`, Pink `#D62293`, Stone
`#E5E5E5`) and the Clarity City font stack, similar in feel to
[contribute.cncf.io](https://contribute.cncf.io/contributors/).

```bash
# Docker Compose
CUSTOM_THEME=./examples/themes/cncf/custom-theme.css \
UI_CONFIG=./examples/themes/cncf/ui-config.json \
make dev
```

```bash
# Kubernetes – mount via ConfigMap (see Helm values ui.customTheme / ui.siteConfig)
kubectl create configmap bomhort-theme --from-file=custom-theme.css=examples/themes/cncf/custom-theme.css
```

The theme reuses colours only. It ships no CNCF logo and does not claim
affiliation; keep the trademark attribution in `ui-config.json` if you
deploy it publicly.
