// Package projectgroup resolves which parent (product) a project belongs to.
//
// Projects stand flat next to each other: the CNCF subproject
// argo-cd/argo-workflows is listed beside argo, an internal service beside
// the product it is part of. Folder names cannot tie them together, because
// they differ between sources (argo/ vs argo-cd/, aeraki-mesh/ vs aeraki/) and
// industry setups often have no folder hierarchy, no GitHub and no repository
// at all. So the parent is resolved from explicit configuration first and from
// signals inside the SBOMs second:
//
//  1. the mapping file (Rules), the escape hatch and the override,
//  2. an explicit assignment at ingest: bucket "parent", the "parent"
//     path-layout token, ?parent= on upload, PARENT,
//  3. a tag that names another project (#398, layout "tag/project"),
//  4. automatically, by owner: repository owner (any forge), the owner in a
//     document name "owner/repo version", the namespace of the root purl,
//     the supplier/manufacturer, in that order.
//
// Automatic grouping only assigns a parent when it is unambiguous. Projects
// sharing an owner form a family; if exactly one family member is a top-level
// project (its name has no "/"), it is the parent of the others. If none is,
// the family is grouped under the owner's name, but only when it has at least
// two members. If several are, nothing is grouped: a shared owner such as
// kubernetes-sigs or a vendor with many unrelated products would otherwise
// lump them together. The mapping file resolves those cases.
//
// Nothing is grouped by similar names ("argo" vs "argo-cd"): a wrong group is
// worse than none.
//
// Resolution runs at query time over all projects, so a changed mapping file
// or bucket config takes effect without re-ingesting.
package projectgroup

import (
	"sort"
	"strings"
)

// Source says how a project's parent was resolved.
type Source string

const (
	SourceConfig   Source = "config"   // mapping file
	SourceExplicit Source = "explicit" // bucket, path layout, ?parent=, PARENT
	SourceTag      Source = "tag"      // a tag naming another project
	SourceRepo     Source = "repo"     // repository owner
	SourceDocument Source = "document" // owner in the document name
	SourcePURL     Source = "purl"     // namespace of the root purl
	SourceSupplier Source = "supplier" // supplier / manufacturer
)

// Signals are the per-project inputs to resolution, aggregated over the
// project's SBOMs (the newest non-empty value of each).
type Signals struct {
	Project        string
	ExplicitParent string
	Tags           []string
	SourceRepo     string
	DocumentName   string
	RootPURL       string
	Supplier       string
}

// Assignment is the resolved parent of one project.
type Assignment struct {
	Parent string `json:"parent"`
	Source Source `json:"source"`
	// Owner is the owner the automatic sources grouped by, as written.
	// Empty for config, explicit and tag assignments.
	Owner string `json:"owner,omitempty"`
}

// Resolve assigns parents to projects. Projects without a parent, and parent
// projects themselves, have no entry. rules may be nil.
func Resolve(signals []Signals, rules *Rules) map[string]Assignment {
	names := make(map[string]bool, len(signals))
	for _, s := range signals {
		names[s.Project] = true
	}

	out := make(map[string]Assignment)
	families := make(map[string][]candidate) // lowercased owner → members

	for _, s := range signals {
		owner, ownerSrc := ownerKey(s)

		// 1. Mapping file.
		if g, ok := rules.match(s, owner); ok {
			if !g.Standalone && g.Parent != s.Project {
				out[s.Project] = Assignment{Parent: g.Parent, Source: SourceConfig}
			}
			continue
		}

		// 2. Explicit assignment at ingest.
		if p := strings.TrimSpace(s.ExplicitParent); p != "" && p != s.Project {
			out[s.Project] = Assignment{Parent: p, Source: SourceExplicit}
			continue
		}

		// 3. A tag naming another project. Sorted so the choice is stable
		//    when a project carries several.
		if p := tagParent(s, names); p != "" {
			out[s.Project] = Assignment{Parent: p, Source: SourceTag}
			continue
		}

		// 4. Automatic, by owner; decided per family below.
		if owner != "" {
			key := strings.ToLower(owner)
			families[key] = append(families[key], candidate{project: s.Project, owner: owner, src: ownerSrc})
		}
	}

	for _, members := range families {
		var tops []candidate
		for _, m := range members {
			if !strings.Contains(m.project, "/") {
				tops = append(tops, m)
			}
		}
		switch {
		case len(tops) == 1:
			head := tops[0].project
			for _, m := range members {
				if m.project != head {
					out[m.project] = Assignment{Parent: head, Source: m.src, Owner: m.owner}
				}
			}
		case len(tops) == 0 && len(members) >= 2:
			label := familyLabel(members[0].owner, members)
			for _, m := range members {
				out[m.project] = Assignment{Parent: label, Source: m.src, Owner: m.owner}
			}
		default:
			// No family, or several top-level projects share the owner:
			// ambiguous, group nothing.
		}
	}

	return out
}

// tagParent returns the alphabetically first tag of s that is the name of
// another project, or "".
func tagParent(s Signals, names map[string]bool) string {
	var hits []string
	for _, t := range s.Tags {
		if t != s.Project && names[t] {
			hits = append(hits, t)
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return hits[0]
}

// candidate is a project awaiting automatic grouping by owner.
type candidate struct {
	project string
	owner   string // as written
	src     Source
}

// familyLabel names a group that has no parent project: the owner as written
// by the alphabetically first member, so the label is stable across runs.
func familyLabel(fallback string, members []candidate) string {
	label, first := fallback, ""
	for _, m := range members {
		if first == "" || m.project < first {
			first, label = m.project, m.owner
		}
	}
	return label
}
