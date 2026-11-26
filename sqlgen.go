package authz

import (
	"fmt"
	"strings"
)

// sqlGen turns "the objects of type T that user U has relation R to" into
// SQL by following the model. It is the ONLY implementation of the model's
// semantics used for decisions: Check binds the object ID, Filter does not.
//
// Every (type, relation, remaining hops) node is described by two parts:
//
//   - a non-recursive CTE with the IDs of the objects the user has the
//     relation to, and
//   - "universal" conditions: SQL booleans that do not depend on the object
//     (today: "the user has role R on the system object", from
//     `R from system`). When one holds, the user has the relation to EVERY
//     object of the type.
//
// Operands of a union node:
//
//	direct user     tuples / column rows whose subject is the user (or user:*)
//	userset         tuples whose subject is S#SR and S.id IN (node S, SR, hops-1)
//	computed        the IDs and conditions of (node T, R2, hops)
//	R2 from R1      rows whose R1 subject is P and P.id IN (node P, R2, hops-1)
//	R2 from system  a universal condition on (node system, R2, hops-1)
//
// An intersection node keeps the IDs that satisfy every term, where a term
// is satisfied by its IDs or by its universal conditions.
//
// A hop into another object (userset, "from") spends one of the hops, so the
// SQL is finite even for recursive models (nested teams, folders in folders)
// and works the same on sqlite, mysql and postgres. Only unions and
// intersections are supported, so the model is monotonic: a cut-off chain
// can only deny, never grant.
type sqlGen struct {
	e     *Engine
	uid   uint64
	nodes map[string]nodeRef
	defs  []cteDef
}

type cteDef struct {
	name string
	sql  string
	args []any
}

// nodeRef is a built node: its CTE name and its universal conditions.
// Conditions reference CTEs by name and carry no arguments of their own.
type nodeRef struct {
	cte   string
	conds []string
}

// frag is one simple SELECT producing a single column "id". idCol is the
// expression to compare when binding the object ID.
type frag struct {
	sql   string
	args  []any
	idCol string
}

const emptySet = "SELECT object_id AS id FROM authz_tuples WHERE 1 = 0"

func newSQLGen(e *Engine, uid uint64) *sqlGen {
	return &sqlGen{e: e, uid: uid, nodes: map[string]nodeRef{}}
}

func anyOf(conds []string) string { return "(" + strings.Join(conds, " OR ") + ")" }

func (g *sqlGen) define(name string, frags []frag) {
	def := cteDef{name: name, sql: emptySet}
	if len(frags) > 0 {
		parts := make([]string, len(frags))
		for i, f := range frags {
			parts[i] = f.sql
			def.args = append(def.args, f.args...)
		}
		def.sql = strings.Join(parts, " UNION ")
	}
	g.defs = append(g.defs, def)
}

// node builds (once) the CTE and conditions of (typ, rel, hops). The
// dependencies of a node are either on the same object through computed
// relations (acyclic, checked when the model is loaded) or one hop down, so
// the recursion terminates.
func (g *sqlGen) node(typ, rel string, hops int) nodeRef {
	hops = g.e.model.budget(typ, rel, hops)
	key := fmt.Sprintf("%s|%s|%d", typ, rel, hops)
	if n, ok := g.nodes[key]; ok {
		return n
	}
	name := fmt.Sprintf("az_%s_%s_%d", typ, rel, hops)
	def, _ := g.e.model.relation(typ, rel)

	var n nodeRef
	if def.op == opIntersection {
		var filters, terms []string
		all := true
		var allConds []string
		for i, t := range def.terms {
			frags, conds := g.termOperands(typ, rel, t, hops, nil)
			tname := fmt.Sprintf("%s_t%d", name, i)
			g.define(tname, frags)
			terms = append(terms, "SELECT id FROM "+tname)
			filter := "id IN (SELECT id FROM " + tname + ")"
			if len(conds) > 0 {
				filter = "(" + filter + " OR " + anyOf(conds) + ")"
				allConds = append(allConds, anyOf(conds))
			} else {
				all = false
			}
			filters = append(filters, filter)
		}
		body := "SELECT id FROM (" + strings.Join(terms, " UNION ") + ") az_pool WHERE " + strings.Join(filters, " AND ")
		g.defs = append(g.defs, cteDef{name: name, sql: body})
		n = nodeRef{cte: name}
		if all {
			n.conds = []string{"(" + strings.Join(allConds, " AND ") + ")"}
		}
	} else {
		frags, conds := g.unionOperands(typ, rel, hops, nil)
		g.define(name, frags)
		n = nodeRef{cte: name, conds: conds}
	}
	g.nodes[key] = n
	return n
}

// boundOperands returns the SELECTs and conditions deciding (typ, rel) for
// one object. Unions are inlined so the ID restriction reaches every SELECT;
// an intersection is read from its CTE.
func (g *sqlGen) boundOperands(typ, rel string, hops int, id uint64) ([]frag, []string) {
	def, ok := g.e.model.relation(typ, rel)
	if !ok {
		return nil, nil
	}
	hops = g.e.model.budget(typ, rel, hops)
	if def.op == opIntersection {
		n := g.node(typ, rel, hops)
		return []frag{{sql: "SELECT id FROM " + n.cte + " WHERE id = ?", args: []any{id}}}, n.conds
	}
	return g.unionOperands(typ, rel, hops, &id)
}

func (g *sqlGen) unionOperands(typ, rel string, hops int, bind *uint64) ([]frag, []string) {
	def, ok := g.e.model.relation(typ, rel)
	if !ok {
		return nil, nil
	}
	hops = g.e.model.budget(typ, rel, hops)
	var frags []frag
	var conds []string
	for _, t := range def.terms {
		f, c := g.termOperands(typ, rel, t, hops, bind)
		frags = append(frags, f...)
		conds = append(conds, c...)
	}
	return frags, conds
}

// termOperands returns the SELECTs and universal conditions of one term.
// With bind set, every SELECT is restricted to that object ID.
func (g *sqlGen) termOperands(typ, rel string, t term, hops int, bind *uint64) ([]frag, []string) {
	col, hasCol := g.e.columns[relKey{typ, rel}]
	var out []frag
	var conds []string
	add := func(f frag) {
		if bind != nil {
			f.sql += " AND " + f.idCol + " = ?"
			f.args = append(f.args, *bind)
		}
		out = append(out, f)
	}

	switch t.kind {
	case termDirect:
		var allowUser, allowEveryone bool
		for _, ref := range t.direct {
			switch {
			case ref.Type == UserType && ref.Wildcard:
				allowEveryone = true
			case ref.Type == UserType && ref.Relation == "":
				allowUser = true
			case ref.Relation != "" && !hasCol && hops > 0:
				inner := g.node(ref.Type, ref.Relation, hops-1)
				base := "SELECT object_id AS id FROM authz_tuples WHERE object_type = ? AND relation = ?" +
					" AND subject_type = ? AND subject_relation = ?"
				args := []any{typ, rel, ref.Type, ref.Relation}
				add(frag{sql: base + " AND subject_id IN (SELECT id FROM " + inner.cte + ")", args: args, idCol: "object_id"})
				if len(inner.conds) > 0 { // the user has the relation to every subject object
					add(frag{sql: base + " AND " + anyOf(inner.conds), args: args, idCol: "object_id"})
				}
			}
		}
		if hasCol {
			if col.SubjectType == UserType && allowUser && g.uid != 0 {
				add(frag{
					sql:   fmt.Sprintf("SELECT %s AS id FROM %s WHERE %s = ?", col.IDColumn, col.Table, col.SubjectColumn),
					args:  []any{g.uid},
					idCol: col.IDColumn,
				})
			}
			return out, conds
		}
		var ids []any
		if allowUser && g.uid != 0 {
			ids = append(ids, g.uid)
		}
		if allowEveryone {
			ids = append(ids, everyoneID)
		}
		if len(ids) > 0 {
			add(frag{
				sql: "SELECT object_id AS id FROM authz_tuples WHERE object_type = ? AND relation = ?" +
					" AND subject_type = ? AND subject_relation = '' AND subject_id IN (?" + strings.Repeat(", ?", len(ids)-1) + ")",
				args:  append([]any{typ, rel, UserType}, ids...),
				idCol: "object_id",
			})
		}

	case termComputed:
		if bind != nil {
			return g.boundOperands(typ, t.computed, hops, *bind)
		}
		n := g.node(typ, t.computed, hops)
		return []frag{{sql: "SELECT id FROM " + n.cte, idCol: "id"}}, n.conds

	case termFrom:
		if hops == 0 {
			return nil, nil
		}
		if g.e.model.isImplicitSystem(typ, t) {
			n := g.node(SystemType, t.rel, hops-1)
			conds = append(conds, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE id = %d)", n.cte, System.ID))
			return nil, append(conds, n.conds...)
		}
		from, _ := g.e.model.relation(typ, t.from)
		fromCol, fromHasCol := g.e.columns[relKey{typ, t.from}]
		for _, ref := range from.directRefs() {
			if _, ok := g.e.model.relation(ref.Type, t.rel); !ok {
				continue
			}
			inner := g.node(ref.Type, t.rel, hops-1)
			if fromHasCol {
				if fromCol.SubjectType != ref.Type {
					continue
				}
				base := fmt.Sprintf("SELECT %s AS id FROM %s WHERE ", fromCol.IDColumn, fromCol.Table)
				add(frag{sql: base + fromCol.SubjectColumn + " IN (SELECT id FROM " + inner.cte + ")", idCol: fromCol.IDColumn})
				if len(inner.conds) > 0 { // the user has the relation to every possible parent
					add(frag{sql: base + fromCol.SubjectColumn + " <> 0 AND " + anyOf(inner.conds), idCol: fromCol.IDColumn})
				}
				continue
			}
			base := "SELECT object_id AS id FROM authz_tuples WHERE object_type = ? AND relation = ?" +
				" AND subject_type = ? AND subject_relation = ''"
			args := []any{typ, t.from, ref.Type}
			add(frag{sql: base + " AND subject_id IN (SELECT id FROM " + inner.cte + ")", args: args, idCol: "object_id"})
			if len(inner.conds) > 0 {
				add(frag{sql: base + " AND " + anyOf(inner.conds), args: args, idCol: "object_id"})
			}
		}
	}
	return out, conds
}

// withDefs prefixes a statement with every CTE the generator defined.
func (g *sqlGen) withDefs(body string, bodyArgs []any) (string, []any) {
	var b strings.Builder
	var args []any
	for i, d := range g.defs {
		if i == 0 {
			b.WriteString("WITH ")
		} else {
			b.WriteString(", ")
		}
		b.WriteString(d.name + " AS (" + d.sql + ")")
		args = append(args, d.args...)
	}
	if len(g.defs) > 0 {
		b.WriteString(" ")
	}
	b.WriteString(body)
	return b.String(), append(args, bodyArgs...)
}

// decision builds `SELECT CASE WHEN EXISTS (<frags>) OR <conds> THEN 1 ELSE 0 END`.
func (g *sqlGen) decision(frags []frag, conds []string) (string, []any, bool) {
	var parts []string
	var args []any
	if len(frags) > 0 {
		sels := make([]string, len(frags))
		for i, f := range frags {
			sels[i] = f.sql
			args = append(args, f.args...)
		}
		parts = append(parts, "EXISTS ("+strings.Join(sels, " UNION ")+")")
	}
	parts = append(parts, conds...)
	if len(parts) == 0 {
		return "", nil, false
	}
	sql, all := g.withDefs("SELECT CASE WHEN "+strings.Join(parts, " OR ")+" THEN 1 ELSE 0 END AS ok", args)
	return sql, all, true
}
