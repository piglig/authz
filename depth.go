package authz

import "math"

// Static depth of a relation: the most object hops (userset or "from") any
// path below it can take, or unbounded when the relation is part of a cycle
// (teams in teams, folders in folders).
//
// The SQL generator builds one set per (type, relation, remaining hops).
// Below its static depth, a relation's set no longer changes: with d hops
// left it already contains everything it could reach with more. So the
// generator caps the budget at the static depth, which is exact, and only
// cyclic relations are expanded level by level up to the hop limit. For an
// acyclic model (no nesting), the cost of a check no longer depends on the
// hop limit.
const unbounded = math.MaxInt

// computeDepths fills m.depths. Called once the model is validated
// (computed relations are acyclic, every reference exists).
func (m *Model) computeDepths() {
	m.depths = map[relKey]int{}
	const visiting = -1
	state := map[relKey]int{} // absent: unvisited, visiting: on the DFS stack
	var visit func(k relKey) int
	visit = func(k relKey) int {
		if d, ok := m.depths[k]; ok {
			return d
		}
		if state[k] == visiting {
			return unbounded // a cycle through k
		}
		state[k] = visiting
		depth := 0
		def, _ := m.relation(k.typ, k.rel)
		for _, t := range def.terms {
			for _, dep := range m.dependencies(k.typ, t) {
				d := visit(dep.key)
				if d == unbounded {
					depth = unbounded
				} else if depth != unbounded && d+dep.cost > depth {
					depth = d + dep.cost
				}
			}
		}
		delete(state, k)
		m.depths[k] = depth
		return depth
	}
	for _, typ := range m.typeNames() {
		for _, rel := range m.types[typ].order {
			visit(relKey{typ, rel})
		}
	}
	// A node that reaches a node on the stack is itself on that cycle, so
	// memoizing "unbounded" for it is exact; nodes visited later reuse it.
}

type dependency struct {
	key  relKey
	cost int // object hops spent: 1 for usersets and "from", 0 for computed relations
}

// dependencies are the relations a term reads, as the SQL generator does.
func (m *Model) dependencies(typ string, t term) []dependency {
	var out []dependency
	switch t.kind {
	case termDirect:
		for _, ref := range t.direct {
			if ref.Relation != "" {
				out = append(out, dependency{relKey{ref.Type, ref.Relation}, 1})
			}
		}
	case termComputed:
		out = append(out, dependency{relKey{typ, t.computed}, 0})
	case termFrom:
		if m.isImplicitSystem(typ, t) {
			return []dependency{{relKey{SystemType, t.rel}, 1}}
		}
		from, _ := m.relation(typ, t.from)
		for _, ref := range from.directRefs() {
			if _, ok := m.relation(ref.Type, t.rel); ok {
				out = append(out, dependency{relKey{ref.Type, t.rel}, 1})
			}
		}
	}
	return out
}

// budget caps the hops of (typ, rel) at its static depth.
func (m *Model) budget(typ, rel string, hops int) int {
	if d, ok := m.depths[relKey{typ, rel}]; ok && d < hops {
		return d
	}
	return hops
}
