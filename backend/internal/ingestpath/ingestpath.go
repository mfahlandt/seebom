// Package ingestpath derives the orthogonal ownership dimensions
// (cluster / namespace / project) from an SBOM's location in the ingestion
// source, using an explicit, operator-configured path layout.
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
// always the filename and is never consumed by the layout. Unset (the
// default) means no derivation happens at all — behaviour is unchanged from
// pre-0.7 releases.
//
// Use "_" as a layout segment to skip a directory level that carries no
// meaning, e.g. "cluster/_/project" for {cluster}/{anything}/{project}/f.json.
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
	// TokenSkip consumes a path level without assigning it to a dimension.
	TokenSkip = "_"
)

// Attributes are the ownership dimensions derived from a path. A field is
// empty when the layout does not declare it or the path is too shallow to
// supply it.
type Attributes struct {
	Cluster   string
	Namespace string
	Project   string
}

// Layout is a parsed INGEST_PATH_LAYOUT. The zero value derives nothing,
// which makes it safe to use unconditionally without a nil/enabled check.
type Layout struct {
	segments []string
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

	for _, s := range raw {
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
		case TokenSkip:
			// Repeats are fine — each just consumes one level.
		default:
			return Layout{}, fmt.Errorf("invalid ingest path layout %q: unknown segment %q (want cluster|namespace|project|_)", spec, s)
		}
		segments = append(segments, s)
	}

	return Layout{segments: segments}, nil
}

// Derive maps the directory portion of key onto the layout.
//
// key is the path relative to the ingestion root: the S3 object key with the
// bucket prefix already stripped, or the path relative to SBOM_DIR. The last
// segment is treated as the filename and is never consumed, so a file sitting
// directly at the root yields no attributes.
//
// A path shallower than the layout fills what it can and leaves the rest
// empty; a deeper path is matched from the left, so extra nesting below the
// declared levels is ignored. Both are deliberately tolerant: a single
// oddly-placed file must not fail an ingestion run.
func (l Layout) Derive(key string) Attributes {
	if !l.Enabled() {
		return Attributes{}
	}

	dirs := splitDirs(key)
	if len(dirs) == 0 {
		return Attributes{}
	}

	var attrs Attributes
	for i, token := range l.segments {
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
		}
	}
	return attrs
}

// splitDirs returns the directory segments of key, excluding the filename and
// any empty segments produced by leading, trailing or doubled separators.
// Backslashes are normalised so Windows-style keys in object storage behave
// the same as POSIX ones.
func splitDirs(key string) []string {
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
		return nil
	}
	return cleaned[:len(cleaned)-1] // drop the filename
}

// Apply fills empty fields of the given dimensions from derived, leaving
// non-empty values untouched. Explicit configuration (per-bucket cluster,
// CLUSTER_NAME, upload params) therefore always outranks path derivation —
// an operator who names a dimension means it, and silently overriding that
// from directory structure would be impossible to debug.
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
