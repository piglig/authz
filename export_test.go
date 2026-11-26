package authz

// CheckSQL exposes the statement Check runs (tests and benchmarks only).
func (e *Engine) CheckSQL(uid uint64, relation string, object Object) (string, []any) {
	g := newSQLGen(e, uid)
	frags, conds := g.boundOperands(object.Type, relation, e.maxHops, object.ID)
	sql, args, _ := g.decision(frags, conds)
	return sql, args
}

// Depth exposes the static depth of a relation (-1: unbounded).
func (e *Engine) Depth(typ, rel string) int {
	d := e.model.depths[relKey{typ, rel}]
	if d == unbounded {
		return -1
	}
	return d
}
