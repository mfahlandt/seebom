package license

import (
	"fmt"
	"strings"
)

// ExpressionMode controls how a compound SPDX license expression such as
// "Apache-2.0 AND BSD-3-Clause AND MIT" or "MIT OR GPL-2.0-only" is folded
// into one Category. Before expressions were evaluated, every compound
// string fell through the exact/prefix lookup and was reported as unknown,
// which flagged packages whose every component is permissive.
type ExpressionMode string

const (
	// ExpressionModeStrict follows SPDX semantics. AND binds the consumer to
	// every operand, so one copyleft operand makes the whole expression
	// copyleft and one unknown operand makes it unknown. OR lets the consumer
	// choose, so one permissive operand makes the whole expression permissive.
	ExpressionModeStrict ExpressionMode = "strict"

	// ExpressionModePermissiveWins treats AND like OR: one permissive operand
	// is enough. Useful for catalogues whose SBOM generators join a package's
	// licenses with AND regardless of whether the package is dual-licensed.
	ExpressionModePermissiveWins ExpressionMode = "permissive-wins"

	// ExpressionModeOff disables expression evaluation. The whole string is
	// looked up as one identifier, which is the pre-#expression behaviour.
	ExpressionModeOff ExpressionMode = "off"
)

// DefaultExpressionMode is used when neither the policy file nor the
// environment sets one. Strict is the default because it never hides a
// copyleft obligation; operators opt into permissive-wins explicitly.
const DefaultExpressionMode = ExpressionModeStrict

// ParseExpressionMode validates an operator-supplied mode string. The empty
// string maps to DefaultExpressionMode so unset config stays unset.
func ParseExpressionMode(s string) (ExpressionMode, error) {
	switch m := ExpressionMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return DefaultExpressionMode, nil
	case ExpressionModeStrict, ExpressionModePermissiveWins, ExpressionModeOff:
		return m, nil
	default:
		return "", fmt.Errorf("invalid license expression mode %q (want strict|permissive-wins|off)", s)
	}
}

// ── Tokenizer ────────────────────────────────────────────────────────────────

type tokenKind int

const (
	tokID tokenKind = iota
	tokAnd
	tokOr
	tokWith
	tokLParen
	tokRParen
)

type token struct {
	kind tokenKind
	text string
}

// tokenize splits an SPDX expression into identifiers, operators and
// parentheses. Operators are matched case-insensitively because real-world
// SBOMs carry "and"/"or" as often as the spec's upper-case form. A comma is
// treated as AND: it only ever appears in free-text license names such as
// "MIT, BSD-3-Clause", and AND is the conservative reading.
func tokenize(expr string) []token {
	var (
		toks []token
		word strings.Builder
	)
	flush := func() {
		if word.Len() == 0 {
			return
		}
		w := word.String()
		word.Reset()
		switch strings.ToUpper(w) {
		case "AND":
			toks = append(toks, token{kind: tokAnd})
		case "OR":
			toks = append(toks, token{kind: tokOr})
		case "WITH":
			toks = append(toks, token{kind: tokWith})
		default:
			toks = append(toks, token{kind: tokID, text: w})
		}
	}
	for _, r := range expr {
		switch r {
		case '(':
			flush()
			toks = append(toks, token{kind: tokLParen})
		case ')':
			flush()
			toks = append(toks, token{kind: tokRParen})
		case ',':
			flush()
			toks = append(toks, token{kind: tokAnd})
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			word.WriteRune(r)
		}
	}
	flush()
	return toks
}

// hasOperator reports whether the token stream contains anything that makes
// it a compound expression. A bare identifier is not worth parsing.
func hasOperator(toks []token) bool {
	for _, t := range toks {
		if t.kind != tokID {
			return true
		}
	}
	return false
}

// ── Parser ───────────────────────────────────────────────────────────────────
//
// Precedence follows the SPDX spec: WITH binds tighter than AND, which binds
// tighter than OR. Parentheses override.
//
//	or-expr   := and-expr  ( OR  and-expr  )*
//	and-expr  := with-expr ( AND with-expr )*
//	with-expr := primary   ( WITH ID )?
//	primary   := '(' or-expr ')' | ID

type nodeKind int

const (
	nodeLeaf nodeKind = iota
	nodeAnd
	nodeOr
)

type exprNode struct {
	kind     nodeKind
	id       string // nodeLeaf: the identifier, or "L WITH E" for an exception
	children []*exprNode
}

type parser struct {
	toks []token
	pos  int
}

func parseExpression(expr string) (*exprNode, error) {
	toks := tokenize(expr)
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty expression")
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token at position %d", p.pos)
	}
	return n, nil
}

func (p *parser) peek() (token, bool) {
	if p.pos >= len(p.toks) {
		return token{}, false
	}
	return p.toks[p.pos], true
}

func (p *parser) parseOr() (*exprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	children := []*exprNode{left}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			break
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return &exprNode{kind: nodeOr, children: children}, nil
}

func (p *parser) parseAnd() (*exprNode, error) {
	left, err := p.parseWith()
	if err != nil {
		return nil, err
	}
	children := []*exprNode{left}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokAnd {
			break
		}
		p.pos++
		right, err := p.parseWith()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return &exprNode{kind: nodeAnd, children: children}, nil
}

func (p *parser) parseWith() (*exprNode, error) {
	prim, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	t, ok := p.peek()
	if !ok || t.kind != tokWith {
		return prim, nil
	}
	p.pos++
	exc, ok := p.peek()
	if !ok || exc.kind != tokID {
		return nil, fmt.Errorf("WITH requires an exception identifier")
	}
	p.pos++
	if prim.kind != nodeLeaf {
		return nil, fmt.Errorf("WITH may only follow a single license identifier")
	}
	return &exprNode{kind: nodeLeaf, id: prim.id + " WITH " + exc.text}, nil
}

func (p *parser) parsePrimary() (*exprNode, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	switch t.kind {
	case tokLParen:
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c.kind != tokRParen {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return inner, nil
	case tokID:
		p.pos++
		return &exprNode{kind: nodeLeaf, id: t.text}, nil
	default:
		return nil, fmt.Errorf("unexpected operator at position %d", p.pos)
	}
}

// leafIDs returns every license identifier in the tree, in source order.
// A WITH clause stays one leaf ("GPL-2.0-only WITH Classpath-exception-2.0").
func (n *exprNode) leafIDs() []string {
	if n.kind == nodeLeaf {
		return []string{n.id}
	}
	var out []string
	for _, c := range n.children {
		out = append(out, c.leafIDs()...)
	}
	return out
}

// ── Evaluation ───────────────────────────────────────────────────────────────

// evaluate folds the tree into one Category under the given mode. lookup
// classifies a single identifier (exact/prefix policy match).
func (n *exprNode) evaluate(mode ExpressionMode, lookup func(string) Category) Category {
	if n.kind == nodeLeaf {
		return lookupLeaf(n.id, lookup)
	}
	cats := make([]Category, 0, len(n.children))
	for _, c := range n.children {
		cats = append(cats, c.evaluate(mode, lookup))
	}
	switch {
	case n.kind == nodeOr, mode == ExpressionModePermissiveWins:
		return combineChoice(cats)
	default:
		return combineConjunction(cats)
	}
}

// lookupLeaf classifies a single leaf. For "L WITH E" the policy may list the
// full clause explicitly; otherwise the exception does not change the
// classification of L — an exception narrows obligations but never turns a
// copyleft license permissive on its own.
func lookupLeaf(id string, lookup func(string) Category) Category {
	if cat := lookup(id); cat != CategoryUnknown {
		return cat
	}
	if base, _, ok := strings.Cut(id, " WITH "); ok {
		return lookup(base)
	}
	// "GPL-2.0+" is the deprecated spelling of "GPL-2.0-or-later".
	if strings.HasSuffix(id, "+") {
		base := strings.TrimSuffix(id, "+")
		if cat := lookup(base + "-or-later"); cat != CategoryUnknown {
			return cat
		}
		return lookup(base)
	}
	return CategoryUnknown
}

// combineChoice is the OR rule: the consumer picks the best option. One
// permissive operand is enough. Failing that, an unknown operand keeps the
// result unknown — it needs review and may turn out permissive — and only an
// all-copyleft choice is copyleft.
func combineChoice(cats []Category) Category {
	sawUnknown := false
	for _, c := range cats {
		switch c {
		case CategoryPermissive:
			return CategoryPermissive
		case CategoryUnknown:
			sawUnknown = true
		}
	}
	if sawUnknown {
		return CategoryUnknown
	}
	return CategoryCopyleft
}

// combineConjunction is the strict AND rule: every operand binds. One
// copyleft operand makes the whole expression copyleft; otherwise one
// unknown operand makes it unknown; only all-permissive is permissive.
func combineConjunction(cats []Category) Category {
	sawUnknown := false
	for _, c := range cats {
		switch c {
		case CategoryCopyleft:
			return CategoryCopyleft
		case CategoryUnknown:
			sawUnknown = true
		}
	}
	if sawUnknown {
		return CategoryUnknown
	}
	return CategoryPermissive
}
