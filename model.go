// Package authz is a relationship-based authorization engine for GORM
// (the Zanzibar model): access is derived from relationships between subjects
// and objects, stored in the application database.
//
//   - Each module describes its resource types in a model.fga file, written in
//     a subset of the OpenFGA modeling language (see ParseModel).
//   - Relationships come from two places: columns of business tables declared
//     with Column (e.g. the owner of a todo is todos.user_id), and explicit
//     tuples in the authz_tuples table (shares, team membership), written in
//     the same transaction as the business change.
//   - Check ("may this user do X to this object?") and Filter ("which objects
//     may this user do X to?") are generated from the model by ONE SQL
//     generator (sqlgen.go), so they cannot disagree.
//
// The decision API follows the shape of the OpenID AuthZEN Authorization API
// (subject, action/relation, resource); the model is a strict subset of
// OpenFGA's, so a project that outgrows this engine can move to OpenFGA or
// SpiceDB without remodeling.
package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// UserType is the type of every principal. Anonymous callers are user 0.
const UserType = "user"

// SystemType is a built-in type with a single object (System) carrying
// application-wide roles. Every type can refer to them as "<role> from system"
// (e.g. define can_delete: owner or admin from system): system is the
// implicit parent of every object. Modules add roles with
//
//	extend type system
//	  relations
//	    define moderator: [user] or admin
const SystemType = "system"

// RoleAdmin is the built-in system role.
const RoleAdmin = "admin"

// implicitSystem is the relation name that refers to the System object.
const implicitSystem = "system"

// baseModel is always part of the model.
const baseModel = `
type user

type system
  relations
    define admin: [user]
`

type termKind int

const (
	termDirect   termKind = iota // [user, team#member, user:*]
	termComputed                 // editor
	termFrom                     // viewer from parent
)

// TypeRef is one allowed subject of a direct relation.
type TypeRef struct {
	Type     string
	Relation string // "member" in team#member; "" for a plain object
	Wildcard bool   // user:* (everyone, including anonymous callers)
}

func (r TypeRef) String() string {
	switch {
	case r.Wildcard:
		return r.Type + ":*"
	case r.Relation != "":
		return r.Type + "#" + r.Relation
	}
	return r.Type
}

type term struct {
	kind     termKind
	direct   []TypeRef
	computed string // termComputed: the relation on the same object
	rel      string // termFrom: <rel> from <from>
	from     string
}

type relationOp int

const (
	opUnion        relationOp = iota // a or b or c
	opIntersection                   // a and b and c
)

type relationDef struct {
	name  string
	op    relationOp
	terms []term
}

// directRefs returns the subject types the relation accepts as tuples.
func (r *relationDef) directRefs() []TypeRef {
	var out []TypeRef
	for _, t := range r.terms {
		if t.kind == termDirect {
			out = append(out, t.direct...)
		}
	}
	return out
}

type typeDef struct {
	name      string
	module    string
	relations map[string]*relationDef
	order     []string
	extends   bool // "extend type system": adds relations to an existing type
}

// Model is the validated union of every module's types.
type Model struct {
	types  map[string]*typeDef
	depths map[relKey]int // static depth of every relation (see depth.go)
}

var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// parseModel parses the supported subset of the OpenFGA DSL:
//
//	type todo
//	  relations
//	    define owner: [user]
//	    define editor: [user, team#member] or owner
//	    define viewer: [user, user:*, team#member] or editor or viewer from parent
//
//	    define can_delete: owner or admin from system
//	    define can_publish: editor and approver from system
//
//	extend type system
//	  relations
//	    define approver: [user] or admin
//
// Supported: direct relations (with usersets and the user:* wildcard),
// computed relations, "X from Y" (including the implicit "X from system"),
// unions with "or" and intersections with "and". A relation is either a
// union or an intersection; to combine them, define a helper relation (the
// same rule as OpenFGA without parentheses). Not supported, and rejected
// with an error: "but not", conditions ("with"), parentheses.
func parseModel(module, text string) ([]*typeDef, error) {
	var types []*typeDef
	var cur *typeDef
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := raw
		if j := strings.Index(line, "#"); j >= 0 && (j == 0 || line[j-1] == ' ' || line[j-1] == '\t') {
			line = line[:j] // comment (a '#' inside team#member is not preceded by a space)
		}
		line = strings.TrimSpace(line)
		fail := func(format string, args ...any) error {
			return fmt.Errorf("authz: %s model.fga line %d: %s", module, i+1, fmt.Sprintf(format, args...))
		}
		switch {
		case line == "", line == "model", line == "relations",
			strings.HasPrefix(line, "schema "), strings.HasPrefix(line, "module "):
			continue
		case strings.HasPrefix(line, "extend type "):
			name := strings.TrimSpace(strings.TrimPrefix(line, "extend type "))
			if name != SystemType {
				return nil, fail("only `extend type %s` is supported (to add application-wide roles)", SystemType)
			}
			cur = &typeDef{name: name, module: module, relations: map[string]*relationDef{}, extends: true}
			types = append(types, cur)
		case strings.HasPrefix(line, "type "):
			name := strings.TrimSpace(strings.TrimPrefix(line, "type "))
			if !identRe.MatchString(name) {
				return nil, fail("invalid type name %q (lowercase letters, digits, _)", name)
			}
			cur = &typeDef{name: name, module: module, relations: map[string]*relationDef{}}
			types = append(types, cur)
		case strings.HasPrefix(line, "define "):
			if cur == nil {
				return nil, fail("define outside of a type")
			}
			name, expr, ok := strings.Cut(strings.TrimPrefix(line, "define "), ":")
			name = strings.TrimSpace(name)
			if !ok || !identRe.MatchString(name) {
				return nil, fail("expected `define <relation>: <expression>`")
			}
			if _, dup := cur.relations[name]; dup {
				return nil, fail("relation %q is defined twice", name)
			}
			if name == implicitSystem && cur.name != SystemType {
				return nil, fail("%q is reserved: it refers to the system object, as in `admin from system`", name)
			}
			rel, err := parseExpr(name, strings.TrimSpace(expr))
			if err != nil {
				return nil, fail("%v", err)
			}
			cur.relations[name] = rel
			cur.order = append(cur.order, name)
		default:
			return nil, fail("unexpected %q", line)
		}
	}
	return types, nil
}

func parseExpr(name, expr string) (*relationDef, error) {
	padded := " " + expr + " "
	for _, unsupported := range []string{" but not ", " with "} {
		if strings.Contains(padded, unsupported) {
			return nil, fmt.Errorf("relation %q uses %q, which this engine does not support", name, strings.TrimSpace(unsupported))
		}
	}
	if strings.ContainsAny(expr, "()") {
		return nil, fmt.Errorf("relation %q uses parentheses, which this engine does not support; define a helper relation instead", name)
	}
	rel := &relationDef{name: name}
	sep := " or "
	hasAnd, hasOr := strings.Contains(padded, " and "), strings.Contains(padded, " or ")
	switch {
	case hasAnd && hasOr:
		return nil, fmt.Errorf("relation %q mixes \"and\" and \"or\"; define a helper relation for one side, e.g. `define reader: viewer or member` then `define %s: reader and ...`", name, name)
	case hasAnd:
		rel.op, sep = opIntersection, " and "
	}
	for _, part := range strings.Split(expr, sep) {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "["):
			if !strings.HasSuffix(part, "]") {
				return nil, fmt.Errorf("relation %q: missing ] in %q", name, part)
			}
			t := term{kind: termDirect}
			for _, ref := range strings.Split(part[1:len(part)-1], ",") {
				r, err := parseTypeRef(strings.TrimSpace(ref))
				if err != nil {
					return nil, fmt.Errorf("relation %q: %w", name, err)
				}
				t.direct = append(t.direct, r)
			}
			rel.terms = append(rel.terms, t)
		case strings.Contains(part, " from "):
			r, from, _ := strings.Cut(part, " from ")
			r, from = strings.TrimSpace(r), strings.TrimSpace(from)
			if !identRe.MatchString(r) || !identRe.MatchString(from) {
				return nil, fmt.Errorf("relation %q: invalid %q", name, part)
			}
			rel.terms = append(rel.terms, term{kind: termFrom, rel: r, from: from})
		case identRe.MatchString(part):
			rel.terms = append(rel.terms, term{kind: termComputed, computed: part})
		default:
			return nil, fmt.Errorf("relation %q: cannot parse %q", name, part)
		}
	}
	return rel, nil
}

func parseTypeRef(s string) (TypeRef, error) {
	switch {
	case strings.HasSuffix(s, ":*"):
		t := strings.TrimSuffix(s, ":*")
		if !identRe.MatchString(t) {
			return TypeRef{}, fmt.Errorf("invalid type reference %q", s)
		}
		return TypeRef{Type: t, Wildcard: true}, nil
	case strings.Contains(s, "#"):
		t, r, _ := strings.Cut(s, "#")
		if !identRe.MatchString(t) || !identRe.MatchString(r) {
			return TypeRef{}, fmt.Errorf("invalid type reference %q", s)
		}
		return TypeRef{Type: t, Relation: r}, nil
	case identRe.MatchString(s):
		return TypeRef{Type: s}, nil
	}
	return TypeRef{}, fmt.Errorf("invalid type reference %q", s)
}

// newModel merges and validates the types of every module.
func newModel(sources []Module) (*Model, error) {
	m := &Model{types: map[string]*typeDef{}}
	all := append([]Module{{Name: "authz", Model: []byte(baseModel)}}, sources...)
	for _, src := range all {
		types, err := parseModel(src.Name, string(src.Model))
		if err != nil {
			return nil, err
		}
		for _, t := range types {
			if t.extends {
				base := m.types[SystemType]
				for _, name := range t.order {
					if _, dup := base.relations[name]; dup {
						return nil, fmt.Errorf("authz: %s model.fga: system role %q is already defined", t.module, name)
					}
					base.relations[name] = t.relations[name]
					base.order = append(base.order, name)
				}
				continue
			}
			if other, dup := m.types[t.name]; dup {
				return nil, fmt.Errorf("authz: type %q is defined by both %s and %s", t.name, other.module, t.module)
			}
			m.types[t.name] = t
		}
	}
	for _, name := range m.typeNames() {
		if err := m.validateType(m.types[name]); err != nil {
			return nil, err
		}
	}
	m.computeDepths()
	return m, nil
}

func (m *Model) typeNames() []string {
	names := make([]string, 0, len(m.types))
	for n := range m.types {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (m *Model) relation(typ, rel string) (*relationDef, bool) {
	t, ok := m.types[typ]
	if !ok {
		return nil, false
	}
	r, ok := t.relations[rel]
	return r, ok
}

func (m *Model) validateType(t *typeDef) error {
	fail := func(rel, format string, args ...any) error {
		return fmt.Errorf("authz: %s model.fga: type %s, relation %s: %s", t.module, t.name, rel, fmt.Sprintf(format, args...))
	}
	for _, name := range t.order {
		for _, tm := range t.relations[name].terms {
			switch tm.kind {
			case termDirect:
				for _, ref := range tm.direct {
					if _, ok := m.types[ref.Type]; !ok {
						return fail(name, "unknown type %q", ref.Type)
					}
					if ref.Wildcard && ref.Type != UserType {
						return fail(name, "only %s:* is supported as a wildcard", UserType)
					}
					if ref.Relation != "" {
						if _, ok := m.relation(ref.Type, ref.Relation); !ok {
							return fail(name, "%s has no relation %q", ref.Type, ref.Relation)
						}
					}
				}
			case termComputed:
				if _, ok := t.relations[tm.computed]; !ok {
					return fail(name, "refers to undefined relation %q", tm.computed)
				}
			case termFrom:
				if m.implicitSystem(t, tm) {
					if t.name == SystemType {
						return fail(name, "`%s from system` cannot be used on the system type itself", tm.rel)
					}
					if _, ok := m.relation(SystemType, tm.rel); !ok {
						return fail(name, "`%s from system`: the system type has no role %q (add it with `extend type system`)", tm.rel, tm.rel)
					}
					continue
				}
				from, ok := t.relations[tm.from]
				if !ok {
					return fail(name, "`%s from %s`: %s is not defined", tm.rel, tm.from, tm.from)
				}
				found := false
				for _, ft := range from.terms {
					if ft.kind != termDirect {
						return fail(name, "`%s from %s`: %s must be a direct relation such as [project]", tm.rel, tm.from, tm.from)
					}
					for _, ref := range ft.direct {
						if ref.Relation != "" || ref.Wildcard {
							return fail(name, "`%s from %s`: %s must list plain object types", tm.rel, tm.from, tm.from)
						}
						if _, ok := m.relation(ref.Type, tm.rel); ok {
							found = true
						}
					}
				}
				if !found {
					return fail(name, "`%s from %s`: no type allowed in %s defines %s", tm.rel, tm.from, tm.from, tm.rel)
				}
			}
		}
	}
	// Computed relations on the same object must not form a cycle.
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fail(name, "is defined in terms of itself")
		case done:
			return nil
		}
		state[name] = visiting
		for _, tm := range t.relations[name].terms {
			if tm.kind == termComputed {
				if err := visit(tm.computed); err != nil {
					return err
				}
			}
		}
		state[name] = done
		return nil
	}
	for _, name := range t.order {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

// implicitSystem reports whether a "X from system" term refers to the
// built-in system object (the type defines no relation named system).
func (m *Model) implicitSystem(t *typeDef, tm term) bool {
	if tm.kind != termFrom || tm.from != implicitSystem {
		return false
	}
	_, own := t.relations[implicitSystem]
	return !own
}

// isImplicitSystem is implicitSystem by type name.
func (m *Model) isImplicitSystem(typ string, tm term) bool {
	t, ok := m.types[typ]
	return ok && m.implicitSystem(t, tm)
}
