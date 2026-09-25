// Package sourcerepo normalises the many ways SBOM documents spell "where the
// source lives" into one canonical (repo URL, ref) pair (#332).
//
// SPDX downloadLocation alone has at least five common shapes for the same
// repository — git+https://host/x/y.git@v1.2.3, git://host/x/y.git,
// git+ssh://git@host/x/y, https://host/x/y, plus NOASSERTION/NONE — and
// CycloneDX vcs references add their own. If every consumer (UI links,
// VEXViper cloning, dedup queries) had to handle that zoo, they would each
// handle a different subset. Normalising once at ingest means the stored
// value is directly usable: an https URL a browser can open and `git clone`
// accepts, with the ref split out.
package sourcerepo

import (
	"net/url"
	"strings"
)

// browseMarkers are the forge URL path segments that separate "the repo" from
// "a ref inside it". Order matters: GitLab's "/-/" forms embed the GitHub
// spelling as a substring and have to win. Tags and branches may legitimately
// contain slashes (release/v1, feature/foo), so most markers take the whole
// remainder as the ref; download URLs are the exception because the remainder
// is an asset filename.
var browseMarkers = []struct {
	marker           string
	firstSegmentOnly bool
}{
	// GitLab
	{"/-/tree/", false},
	{"/-/tags/", false},
	{"/-/releases/", false},
	{"/-/commit/", true},
	{"/-/commits/", false},
	// Gitea / Forgejo / Codeberg
	{"/src/branch/", false},
	{"/src/tag/", false},
	{"/src/commit/", true},
	// GitHub (also matched by Gitea/GitLab for the plain forms)
	{"/releases/download/", true},
	{"/releases/tag/", false},
	{"/tree/", false},
	{"/commit/", true},
	{"/commits/", false},
}

// knownForgeHosts are hosts where any "/owner/repo" path is a repository by
// construction. Used only by NormalizeStrict; Normalize accepts any host
// because a downloadLocation is already a statement of intent.
var knownForgeHosts = map[string]bool{
	"github.com":              true,
	"gitlab.com":              true,
	"bitbucket.org":           true,
	"codeberg.org":            true,
	"gitea.com":               true,
	"gitee.com":               true,
	"sr.ht":                   true,
	"git.sr.ht":               true,
	"salsa.debian.org":        true,
	"framagit.org":            true,
	"invent.kde.org":          true,
	"gitlab.freedesktop.org":  true,
	"gitlab.gnome.org":        true,
	"git.kernel.org":          true,
	"opendev.org":             true,
	"gerrit.googlesource.com": true,
	"go.googlesource.com":     true,
}

// Normalize turns a raw VCS locator from an SBOM into a canonical
// (repo, ref) pair. It returns ("", "") for anything that does not clearly
// identify a repository — the caller stores ” (= unknown) rather than a
// guess, because a wrong repo silently sends triage tooling to clone the
// wrong code, which is worse than no value at all.
//
// Handled input shapes:
//
//	git+https://github.com/x/y.git@v1.2.3   -> https://github.com/x/y, v1.2.3
//	git+ssh://git@github.com/x/y.git        -> https://github.com/x/y
//	git://github.com/x/y.git                -> https://github.com/x/y
//	ssh://git@github.com/x/y                -> https://github.com/x/y
//	git@github.com:x/y.git                  -> https://github.com/x/y (scp-like)
//	https://github.com/x/y/tree/main        -> https://github.com/x/y, main
//	https://github.com/x/y/releases/tag/v1  -> https://github.com/x/y, v1     (#355)
//	https://github.com/x/y/commit/<sha>     -> https://github.com/x/y, <sha>  (#355)
//	http(s)://github.com/x/y(.git)(@ref)    -> https://github.com/x/y, ref
//	NOASSERTION / NONE / "" / non-VCS URLs  -> "", ""
func Normalize(raw string) (repo, ref string) {
	repo, ref, _ = normalize(raw)
	return repo, ref
}

// NormalizeStrict is Normalize for inputs that are only *conventionally* a
// repository locator — SPDX documentNamespace (#355), CycloneDX distribution
// references. Normalize accepts any http(s) URL with a path because a
// downloadLocation is already a statement of intent; a documentNamespace is
// not: syft writes "https://anchore.com/syft/dir/<name>-<uuid>", others use
// "https://spdx.org/spdxdocs/<name>-<uuid>", and neither is clonable.
//
// NormalizeStrict therefore additionally requires the URL to be *evidently* a
// repository: a git/ssh/scp locator, a ".git" or "@ref" suffix, a forge
// browse marker (/tree/, /releases/tag/, /commit/, …) or a well-known forge
// host. Everything else yields ("", "").
func NormalizeStrict(raw string) (repo, ref string) {
	repo, ref, evident := normalize(raw)
	if !evident {
		return "", ""
	}
	return repo, ref
}

// normalize does the work for Normalize and NormalizeStrict. evident reports
// whether the input was structurally a repository locator rather than merely
// a URL with a path.
func normalize(raw string) (repo, ref string, evident bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	switch strings.ToUpper(s) {
	case "NOASSERTION", "NONE":
		return "", "", false
	}

	// SPDX 2.x VCS prefix: "git+https://…", "hg+https://…" etc. Only git is
	// worth normalising — the others are rare enough that a wrong guess is
	// likelier than a hit.
	if strings.HasPrefix(s, "git+") {
		s = s[len("git+"):]
		evident = true
	}

	// scp-like syntax (git@host:path) has no scheme and url.Parse mangles it;
	// rewrite it to ssh:// form first.
	if !strings.Contains(s, "://") {
		if at := strings.Index(s, "@"); at > 0 && strings.Contains(s[at:], ":") {
			s = "ssh://" + strings.Replace(s, ":", "/", 1)
			evident = true
		} else {
			return "", "", false // bare words ("local", file paths) are not repositories
		}
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", "", false
	}

	switch u.Scheme {
	case "http", "https":
		// keep
	case "git", "ssh":
		// Normalise to https: it is the one form both a browser and
		// `git clone` accept, and it carries no usernames.
		u.Scheme = "https"
		evident = true
	default:
		// file://, pkg:, oci://, urn: etc. do not name a source repository.
		return "", "", false
	}

	if u.Host == "" {
		return "", "", false
	}
	u.User = nil // never store credentials or ssh usernames

	host := strings.ToLower(u.Host)
	if knownForgeHosts[host] {
		evident = true
	}

	path := strings.TrimSuffix(u.Path, "/")

	// SPDX "@ref" suffix (git+https://…/y.git@v1.2.3). Split before trimming
	// ".git" so "y.git@ref" resolves cleanly.
	if at := strings.LastIndex(path, "@"); at > 0 {
		ref = path[at+1:]
		path = path[:at]
		evident = true
	}

	if strings.HasSuffix(path, ".git") {
		path = strings.TrimSuffix(path, ".git")
		evident = true
	}

	// Forge browse-URLs: everything before the marker is the repo, the path
	// after it is (or starts with) the ref. GitLab's "/-/…" variants contain
	// the plain GitHub markers as substrings, so they must be tried first or
	// the repo would keep a trailing "/-".
	//
	// Release URLs (#355) matter because they are what real-world SPDX
	// documentNamespaces look like: every one of the 500 CNCF SBOMs surveyed
	// carries "https://github.com/org/repo/releases/tag/vX.Y.Z" there.
	for _, m := range browseMarkers {
		i := strings.Index(path, m.marker)
		if i <= 0 {
			continue
		}
		rest := strings.Trim(path[i+len(m.marker):], "/")
		if ref == "" && rest != "" {
			if m.firstSegmentOnly {
				// "/releases/download/<ref>/<asset>": only the first segment
				// is the ref, the remainder names an artefact.
				rest, _, _ = strings.Cut(rest, "/")
			}
			ref = rest
		}
		path = path[:i]
		evident = true
		break
	}

	// A bare "/releases" or "/tags" listing page names the repo but no ref.
	for _, suffix := range []string{"/-/releases", "/-/tags", "/releases", "/tags", "/commits"} {
		if strings.HasSuffix(path, suffix) && len(path) > len(suffix) {
			path = strings.TrimSuffix(path, suffix)
			evident = true
			break
		}
	}

	if path == "" || path == "/" {
		return "", "", false // a bare host is not a repository
	}

	// Fragments sometimes carry the ref (…#v1.2.3); use it only as fallback.
	if ref == "" && u.Fragment != "" {
		ref = u.Fragment
	}

	return "https://" + host + path, strings.TrimSpace(ref), evident
}

// IsValidRepoURL reports whether s is acceptable as an explicitly supplied
// source_repo (upload header, PATCH). Explicit values are held to a stricter
// standard than extracted ones: they come from an authenticated caller who
// can be told "no", so only well-formed http(s) URLs with a host and path are
// let through. Everything else risks storing values that break `git clone`
// or UI links fleet-wide.
func IsValidRepoURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") &&
		u.Host != "" &&
		u.User == nil &&
		len(strings.Trim(u.Path, "/")) > 0
}

// IsValidRef reports whether s is acceptable as an explicitly supplied
// source_ref: a git ref or SHA — no whitespace, no control characters, and
// bounded (git refs cap out well under this; anything longer is garbage or an
// injection attempt).
func IsValidRef(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}
