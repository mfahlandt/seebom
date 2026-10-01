package projectgroup

import (
	"net/url"
	"regexp"
	"strings"
)

// Owner keys: who owns a project, derived from signals that any SBOM may
// carry. Projects with the same owner key belong to the same family; the
// resolver then decides which family member, if any, is the parent.
//
// Every extractor returns the owner as written (for display) or "" when the
// signal does not identify an owner. Comparison happens on the lowercased
// form. Host names are dropped where they would only get in the way of a
// match ("github.com/argoproj" and "argoproj" are the same owner).

// ownerFromRepo returns the owner path of a repository URL: everything
// between the host and the repository name, so GitLab subgroups are kept
// ("gitlab.example.com/payments/core/api" → "payments/core"). Azure DevOps and
// Bitbucket Server URLs, whose paths carry fixed markers, are special-cased.
func ownerFromRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	u, err := url.Parse(repo)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Host)
	segs := splitPath(u.Path)

	switch {
	// https://dev.azure.com/{org}/{project}/_git/{repo}
	case host == "dev.azure.com" && len(segs) >= 4 && segs[2] == "_git":
		return segs[0] + "/" + segs[1]
	// https://{org}.visualstudio.com/{project}/_git/{repo}
	case strings.HasSuffix(host, ".visualstudio.com") && len(segs) >= 3 && segs[1] == "_git":
		return strings.TrimSuffix(host, ".visualstudio.com") + "/" + segs[0]
	// Bitbucket Server: /scm/{project}/{repo} and /projects/{P}/repos/{repo}
	case len(segs) >= 3 && segs[0] == "scm":
		return segs[1]
	case len(segs) >= 4 && segs[0] == "projects" && segs[2] == "repos":
		return segs[1]
	}

	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs[:len(segs)-1], "/")
}

// ownerFromDocumentName reads "owner/repo" from a document name like
// "argoproj/argo-workflows v3.7.16", the shape many generators (waybill,
// CI tooling) use. Only the first whitespace-separated token is considered;
// a leading registry or host ("ghcr.io/argoproj/argocd") is dropped. A name
// without a "/" names no owner.
func ownerFromDocumentName(name string) string {
	tok := strings.TrimSpace(name)
	if i := strings.IndexAny(tok, " \t"); i >= 0 {
		tok = tok[:i]
	}
	if tok == "" || strings.Contains(tok, "://") {
		return ""
	}
	segs := splitPath(tok)
	if len(segs) < 2 {
		return ""
	}
	if len(segs) > 2 && strings.Contains(segs[0], ".") {
		segs = segs[1:]
	}
	return strings.Join(segs[:len(segs)-1], "/")
}

var goMajorVersion = regexp.MustCompile(`^v[0-9]+$`)

// ownerFromPURL returns the namespace of a package URL, normalised per type so
// it names an owner:
//
//	pkg:maven/com.acme.payments/ledger@2.0.1      → com.acme.payments
//	pkg:npm/%40acme/ui@1.0.0                      → acme
//	pkg:golang/github.com/argoproj/argo-cd/v3@v3  → argoproj
//	pkg:github/argoproj/argo-cd@v3.4.7            → argoproj
//	pkg:oci/argocd?repository_url=quay.io/argoproj/argocd → argoproj
//
// A purl without a namespace (pkg:generic/foo, pkg:pypi/requests) names no
// owner.
func ownerFromPURL(purl string) string {
	p := strings.TrimSpace(purl)
	if len(p) < 4 || !strings.EqualFold(p[:4], "pkg:") {
		return ""
	}
	p = p[4:]
	p, _, _ = strings.Cut(p, "#")
	p, rawQualifiers, _ := strings.Cut(p, "?")

	typ, rest, ok := strings.Cut(p, "/")
	if !ok {
		return ""
	}
	typ = strings.ToLower(typ)
	rest = strings.TrimLeft(rest, "/")
	// The version follows the last "@" after the last "/" (an npm scope "@acme"
	// sits before it and stays).
	if at := strings.LastIndex(rest, "@"); at > strings.LastIndex(rest, "/") {
		rest = rest[:at]
	}

	segs := splitPath(rest)
	for i, s := range segs {
		if dec, err := url.PathUnescape(s); err == nil {
			segs[i] = dec
		}
	}
	if len(segs) == 0 {
		return ""
	}
	ns, name := segs[:len(segs)-1], segs[len(segs)-1]

	switch typ {
	case "golang":
		// Module major-version suffix: .../argo-cd/v3 → the module is argo-cd.
		if goMajorVersion.MatchString(name) && len(ns) > 0 {
			ns = ns[:len(ns)-1]
		}
		if len(ns) > 1 && strings.Contains(ns[0], ".") {
			ns = ns[1:]
		}
	case "npm":
		if len(ns) > 0 {
			ns[0] = strings.TrimPrefix(ns[0], "@")
		}
	case "oci", "docker":
		if len(ns) == 0 {
			if q, err := url.ParseQuery(rawQualifiers); err == nil {
				if r := q.Get("repository_url"); r != "" {
					rs := splitPath(r)
					if len(rs) > 2 && strings.Contains(rs[0], ".") {
						rs = rs[1:]
					}
					if len(rs) >= 2 {
						ns = rs[:len(rs)-1]
					}
				}
			}
		}
	}

	if len(ns) == 0 {
		return ""
	}
	return strings.Join(ns, "/")
}

// splitPath splits a slash-separated path into its non-empty segments.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ownerKey returns the owner of a project from its signals, in the order of
// how directly each signal names an owner, plus the source it came from.
// display is the owner as written; compare on strings.ToLower(display).
func ownerKey(s Signals) (display string, src Source) {
	if o := ownerFromRepo(s.SourceRepo); o != "" {
		return o, SourceRepo
	}
	if o := ownerFromDocumentName(s.DocumentName); o != "" {
		return o, SourceDocument
	}
	if o := ownerFromPURL(s.RootPURL); o != "" {
		return o, SourcePURL
	}
	if o := strings.TrimSpace(s.Supplier); o != "" {
		return o, SourceSupplier
	}
	return "", ""
}
