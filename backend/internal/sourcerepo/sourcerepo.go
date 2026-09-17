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
//	http(s)://github.com/x/y(.git)(@ref)    -> https://github.com/x/y, ref
//	NOASSERTION / NONE / "" / non-VCS URLs  -> "", ""
func Normalize(raw string) (repo, ref string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	switch strings.ToUpper(s) {
	case "NOASSERTION", "NONE":
		return "", ""
	}

	// SPDX 2.x VCS prefix: "git+https://…", "hg+https://…" etc. Only git is
	// worth normalising — the others are rare enough that a wrong guess is
	// likelier than a hit.
	s = strings.TrimPrefix(s, "git+")

	// scp-like syntax (git@host:path) has no scheme and url.Parse mangles it;
	// rewrite it to ssh:// form first.
	if !strings.Contains(s, "://") {
		if at := strings.Index(s, "@"); at > 0 && strings.Contains(s[at:], ":") {
			s = "ssh://" + strings.Replace(s, ":", "/", 1)
		} else {
			return "", "" // bare words ("local", file paths) are not repositories
		}
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", ""
	}

	switch u.Scheme {
	case "http", "https":
		// keep
	case "git", "ssh":
		// Normalise to https: it is the one form both a browser and
		// `git clone` accept, and it carries no usernames.
		u.Scheme = "https"
	default:
		// file://, pkg:, oci:// etc. do not name a source repository.
		return "", ""
	}

	if u.Host == "" {
		return "", ""
	}
	u.User = nil // never store credentials or ssh usernames

	path := strings.TrimSuffix(u.Path, "/")

	// SPDX "@ref" suffix (git+https://…/y.git@v1.2.3). Split before trimming
	// ".git" so "y.git@ref" resolves cleanly.
	if at := strings.LastIndex(path, "@"); at > 0 {
		ref = path[at+1:]
		path = path[:at]
	}

	path = strings.TrimSuffix(path, ".git")

	// Forge browse-URLs: https://host/x/y/tree/<ref> (GitHub/GitLab/Gitea).
	// The path after the marker is the ref; everything before is the repo.
	// GitLab's "/-/tree/" contains "/tree/", so it must be tried first or the
	// repo would keep a trailing "/-".
	for _, marker := range []string{"/-/tree/", "/src/branch/", "/tree/"} {
		if i := strings.Index(path, marker); i > 0 {
			if ref == "" {
				ref = strings.Trim(path[i+len(marker):], "/")
			}
			path = path[:i]
			break
		}
	}

	if path == "" || path == "/" {
		return "", "" // a bare host is not a repository
	}

	// Fragments sometimes carry the ref (…#v1.2.3); use it only as fallback.
	if ref == "" && u.Fragment != "" {
		ref = u.Fragment
	}

	return "https://" + u.Host + path, strings.TrimSpace(ref)
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
