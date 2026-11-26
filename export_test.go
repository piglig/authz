package authz

// Depth exposes the static depth of a relation (-1: unbounded).
func (e *Engine) Depth(typ, rel string) int {
	d := e.model.depths[relKey{typ, rel}]
	if d == unbounded {
		return -1
	}
	return d
}
