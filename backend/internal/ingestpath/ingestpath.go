// Package ingestpath derives the orthogonal ownership dimensions
// (cluster / namespace / project) and grouping tags from an SBOM's location
// in the ingestion source, using an explicit, operator-configured path layout.
//
// Rationale (#138, #57): BOMHort ingests from buckets and directories that
// teams already organise hierarchically — typically one directory level per
// cluster, then per namespace, then per project. Rather than guessing that
// structure (which silently mislabels data when the guess is wrong), the
// layout is declared explicitly:
//
//	INGEST_PATH_LAYOUT="cluster/namespace/project"
//
// Each segment of the layout maps positionally onto the leading path segments
// of the object key / relative file path. The final segment of the path is
// the filename and is only consumed by the explicit "file" token (below).
// Unset (the default) means no derivation happens at all — behaviour is
// unchanged from pre-0.7 releases.
//
// Use "_" as a layout segment to skip a directory level that carries no
// meaning, e.g. "cluster/_/project" for {cluster}/{anything}/{project}/f.json.
//
// Use "tag" (#398) to turn a directory level into a grouping label instead of
// an ownership dimension. It may repeat — each occurrence adds one tag. This
// is how a parent/sub-project hierarchy is expressed without a second
// identity column: a bucket laid out as {parent}/{subproject}/{version}/f.json
// with layout "tag/project" yields project=subproject, tags=[parent], and the
// parent's own project page can then list everything tagged with its name.
//
// Use "file" (#398) as the *last* layout segment to take the project from the
// filename with its extensions stripped: {tier}/{issue}/{org}/{repo}.spdx.json
// with layout "tag/_/tag/file" yields project=repo, tags=[tier, org]. It
// exists because a common real-world shape names the file after the project
// and uses directories for review metadata — the org there is a grouping,
// not the identity. "file" and "project" are mutually exclusive.
package ingestpath

import (
	"fmt"
	"strings"
)

// Layout segment tokens.
const (
	TokenCluster   = "cluster"
	TokenNamespace = "namespace"
	TokenProject   = "project"
	// TokenTag turns a directory level into a grouping label (#357 tags).
	// Unlike the dimensions it may appear more than once.
	TokenTag = "tag"
	// TokenFile assigns the filename (minus extensions) to project. Only
	// valid as the last segment — it is the one token that consumes the
	// filename rather than a directory.
	TokenFile = "file"
	// TokenSkip consumes a path level without assigning it to a dimension.
	TokenSkip = "_"
)

// Attributes are the ownership dimensions and grouping tags derived from a
// path. A field is empty when the layout does not declare it or the path is
// too shallow to supply it. Tags are in path order and not yet normalised;
// callers merge them through the tags package like every other tag source.
type Attributes struct {
	Cluster   string
	Namespace string
	Project   string
	Tags      []string
}

// Layout is a parsed INGEST_PATH_LAYOUT. The zero value derives nothing,
// which makes it safe to use unconditionally without a nil/enabled check.
type Layout struct {
	segments []string
	// fileProject is set when the last segment is TokenFile. Kept as a flag
	// rather than re-scanning segments on every Derive call.
	fileProject bool
}

// Enabled reports whether this layout derives anything at all.
func (l Layout) Enabled() bool { return len(l.segments) > 0 }

// String renders the layout back to its canonical configuration form.
func (l Layout) String() string { return strings.Join(l.segments, "/") }

// ParseLayout parses a layout spec like "cluster/namespace/project".
// An empty spec yields a disabled (zero-value) layout and no error, so
// callers can pass unset configuration straight through.
func ParseLayout(spec string) (Layout, error) {
	spec = strings.Trim(strings.TrimSpace(spec), "/")
	if spec == "" {
		return Layout{}, nil
	}

	raw := strings.Split(spec, "/")
	segments := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))

	for i, s := range raw {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return Layout{}, fmt.Errorf("invalid ingest path layout %q: empty segment", spec)
		}
		switch s {
		case TokenCluster, TokenNamespace, TokenProject:
			// A dimension appearing twice is always a config mistake: the
			// second occurrence would silently overwrite the first.
			if seen[s] {
				return Layout{}, fmt.Errorf("invalid ingest path layout %q: duplicate segment %q", spec, s)
			}
			seen[s] = true
		case TokenFile:
			// The filename is one thing; it can only feed one token, and it
			// has to be the last one because everything before it is a
			// directory by definition.
			if i != len(raw)-1 {
				return Layout{}, fmt.Errorf("invalid ingest path layout %q: %q must be the last segment", spec, s)
			}
			if seen[TokenProject] {
				return Layout{}, fmt.Errorf("invalid ingest path layout %q: %q and %q both set project", spec, TokenFile, TokenProject)
			}
			seen[TokenProject] = true
		case TokenSkip, TokenTag:
			// Repeats are fine — each just consumes one level.
		default:
			return Layout{}, fmt.Errorf("invalid ingest path layout %q: unknown segment %q (want cluster|namespace|project|tag|file|_)", spec, s)
		}
		segments = append(segments, s)
	}

	return Layout{
		segments:    segments,
		fileProject: segments[len(segments)-1] == TokenFile,
	}, nil
}

// Derive maps the directory portion of key onto the layout.
//
// key is the path relative to the ingestion root: the S3 object key with the
// bucket prefix already stripped, or the path relative to SBOM_DIR. The last
// segment is treated as the filename and is only consumed by a trailing
// "file" token, so a file sitting directly at the root yields no directory
// attributes.
//
// A path shallower than the layout fills what it can and leaves the rest
// empty; a deeper path is matched from the left, so extra nesting below the
// declared levels is ignored. Both are deliberately tolerant: a single
// oddly-placed file must not fail an ingestion run.
func (l Layout) Derive(key string) Attributes {
	if !l.Enabled() {
		return Attributes{}
	}

	dirs, file := splitPath(key)
	if len(dirs) == 0 && file == "" {
		return Attributes{}
	}

	var attrs Attributes
	dirTokens := l.segments
	if l.fileProject {
		dirTokens = dirTokens[:len(dirTokens)-1]
		attrs.Project = stripExtensions(file)
	}

	for i, token := range dirTokens {
		if i >= len(dirs) {
			break
		}
		switch token {
		case TokenCluster:
			attrs.Cluster = dirs[i]
		case TokenNamespace:
			attrs.Namespace = dirs[i]
		case TokenProject:
			attrs.Project = dirs[i]
		case TokenTag:
			attrs.Tags = append(attrs.Tags, dirs[i])
		}
	}
	return attrs
}

// splitPath returns the directory segments and the filename of key,
// excluding any empty segments produced by leading, trailing or doubled
// separators. Backslashes are normalised so Windows-style keys in object
// storage behave the same as POSIX ones.
func splitPath(key string) (dirs []string, file string) {
	key = strings.ReplaceAll(key, "\\", "/")
	parts := strings.Split(key, "/")

	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// "." and ".." are never meaningful dimension names and would produce
		// nonsense labels if a relative path leaked through.
		if p == "" || p == "." || p == ".." {
			continue
		}
		cleaned = append(cleaned, p)
	}

	if len(cleaned) == 0 {
		return nil, ""
	}
	return cleaned[:len(cleaned)-1], cleaned[len(cleaned)-1]
}

// stripExtensions removes every dotted suffix from a filename: "k2s.spdx.json"
// and "app.cdx.json" both become their bare stem. Everything after the first
// dot is treated as extension because SBOM files stack format markers
// (.spdx.json, .cdx.json, .openvex.json) and there is no reliable way to tell
// a version dot from a format dot — "app-1.2.3.spdx.json" is the operator's
// problem to lay out with a "project" directory instead. A name that is
// nothing but an extension (".json") yields "" rather than a nonsense label.
func stripExtensions(file string) string {
	if i := strings.IndexByte(file, '.'); i >= 0 {
		return file[:i]
	}
	return file
}

// Apply fills empty fields of the given dimensions from derived, leaving
// non-empty values untouched. Explicit configuration (per-bucket cluster,
// CLUSTER_NAME, upload params) therefore always outranks path derivation —
// an operator who names a dimension means it, and silently overriding that
// from directory structure would be impossible to debug.
//
// Tags are not handled here: they are additive rather than either/or, so the
// caller merges Attributes.Tags with its configured tags through the tags
// package, which also normalises them.
func Apply(derived Attributes, cluster, namespace, project *string) {
	if *cluster == "" {
		*cluster = derived.Cluster
	}
	if *namespace == "" {
		*namespace = derived.Namespace
	}
	if *project == "" {
		*project = derived.Project
	}
}
