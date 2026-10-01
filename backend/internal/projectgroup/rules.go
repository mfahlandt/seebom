package projectgroup

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	json "github.com/goccy/go-json"
)

// File is the on-disk shape of the mapping file (PROJECT_GROUPS_FILE,
// default /data/config/project-groups.json):
//
//	{
//	  "version": "1.0.0",
//	  "groups": [
//	    { "parent": "argo", "match": { "projects": ["argo-cd/*"] } },
//	    { "parent": "Payments Platform",
//	      "match": { "owners": ["acme-payments"], "suppliers": ["ACME Corp"] } },
//	    { "standalone": true, "match": { "owners": ["kubernetes-sigs"] },
//	      "reason": "shared org, the projects are unrelated" }
//	  ]
//	}
//
// Groups are evaluated in file order; the first whose match applies wins.
// Within one match the criteria are alternatives: a project matches when any
// listed value matches.
type File struct {
	Version string  `json:"version"`
	Groups  []Group `json:"groups"`
}

// Group assigns every matching project to Parent, or with Standalone keeps
// matching projects out of any group, including the automatic ones.
type Group struct {
	Parent     string `json:"parent,omitempty"`
	Standalone bool   `json:"standalone,omitempty"`
	Match      Match  `json:"match"`
	Reason     string `json:"reason,omitempty"`
}

// Match selects projects. Projects and Repos are glob patterns ("*" matches
// any run of characters, "/" included; "?" one character). Owners and
// Suppliers compare exactly. Everything is case-insensitive.
type Match struct {
	Projects  []string `json:"projects,omitempty"`
	Repos     []string `json:"repos,omitempty"`
	Owners    []string `json:"owners,omitempty"`
	Suppliers []string `json:"suppliers,omitempty"`
}

// Rules is a validated, compiled mapping file. The zero value and nil have
// no rules.
type Rules struct {
	groups []compiledGroup
}

type compiledGroup struct {
	Group
	projects  []*regexp.Regexp
	repos     []*regexp.Regexp
	owners    map[string]bool
	suppliers map[string]bool
}

// ParseRules validates and compiles a mapping file.
func ParseRules(data []byte) (*Rules, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("invalid project groups file: %w", err)
	}
	r := &Rules{}
	for i, g := range f.Groups {
		g.Parent = strings.TrimSpace(g.Parent)
		switch {
		case g.Parent == "" && !g.Standalone:
			return nil, fmt.Errorf("invalid project groups file: groups[%d] needs a parent or standalone: true", i)
		case g.Parent != "" && g.Standalone:
			return nil, fmt.Errorf("invalid project groups file: groups[%d] sets both parent and standalone", i)
		}
		m := g.Match
		if len(m.Projects)+len(m.Repos)+len(m.Owners)+len(m.Suppliers) == 0 {
			return nil, fmt.Errorf("invalid project groups file: groups[%d] has an empty match", i)
		}
		cg := compiledGroup{Group: g, owners: lowerSet(m.Owners), suppliers: lowerSet(m.Suppliers)}
		for _, p := range m.Projects {
			cg.projects = append(cg.projects, globRegexp(p))
		}
		for _, p := range m.Repos {
			cg.repos = append(cg.repos, globRegexp(p))
		}
		r.groups = append(r.groups, cg)
	}
	return r, nil
}

// LoadRules reads and compiles the mapping file at path. A missing file is
// not an error: it returns (nil, nil), which means "no explicit rules".
func LoadRules(path string) (*Rules, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read project groups file: %w", err)
	}
	return ParseRules(data)
}

// Len returns the number of groups in the file.
func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.groups)
}

// match returns the first group that applies to a project with the given
// signals and owner key.
func (r *Rules) match(s Signals, owner string) (Group, bool) {
	if r == nil {
		return Group{}, false
	}
	owner = strings.ToLower(owner)
	supplier := strings.ToLower(strings.TrimSpace(s.Supplier))
	for _, g := range r.groups {
		if anyMatch(g.projects, s.Project) || anyMatch(g.repos, s.SourceRepo) ||
			(owner != "" && g.owners[owner]) || (supplier != "" && g.suppliers[supplier]) {
			return g.Group, true
		}
	}
	return Group{}, false
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	if s == "" {
		return false
	}
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// globRegexp compiles a glob ("*" any run including "/", "?" one character)
// into an anchored, case-insensitive regexp. Everything else is literal.
func globRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range strings.TrimSpace(glob) {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func lowerSet(vals []string) map[string]bool {
	set := make(map[string]bool, len(vals))
	for _, v := range vals {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			set[v] = true
		}
	}
	return set
}
