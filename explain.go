package authz

import (
	"context"
	"fmt"
)

// Explain re-evaluates a decision one relationship at a time and returns the
// chain of facts that grants access (or nil when access is denied):
//
//	task:42#editor  <-  editor from parent
//	project:7#editor  <-  team:3#member
//	team:3#member  <-  user:9
//
// It is a second, deliberately naive implementation of the model: it walks
// the data with one small query per step instead of generating SQL. Use it
// for debugging and support. Tests compare it with Check and Filter on
// random data, which is what guards the SQL generator.
func (e *Engine) Explain(ctx context.Context, subject Subject, relation string, object Object) (allowed bool, path []string, err error) {
	if !e.HasRelation(object.Type, relation) {
		return false, nil, fmt.Errorf("authz: type %q has no relation %q", object.Type, relation)
	}
	return e.eval(ctx, subject.UserID, object, relation, e.maxHops)
}

func (e *Engine) eval(ctx context.Context, uid uint64, obj Object, rel string, hops int) (bool, []string, error) {
	def, _ := e.model.relation(obj.Type, rel)
	here := fmt.Sprintf("%s#%s", obj, rel)

	if def.op == opIntersection {
		var path []string
		for i, t := range def.terms {
			ok, sub, err := e.evalTerm(ctx, uid, obj, rel, t, hops)
			if err != nil || !ok {
				return false, nil, err
			}
			path = append(path, fmt.Sprintf("%s  <-  and (%d/%d)", here, i+1, len(def.terms)))
			path = append(path, sub...)
		}
		return true, path, nil
	}
	for _, t := range def.terms {
		ok, path, err := e.evalTerm(ctx, uid, obj, rel, t, hops)
		if err != nil || ok {
			return ok, path, err
		}
	}
	return false, nil, nil
}

// evalTerm evaluates one term of a relation.
func (e *Engine) evalTerm(ctx context.Context, uid uint64, obj Object, rel string, t term, hops int) (bool, []string, error) {
	here := fmt.Sprintf("%s#%s", obj, rel)
	{
		switch t.kind {
		case termDirect:
			subjects, err := e.subjects(ctx, obj, rel)
			if err != nil {
				return false, nil, err
			}
			for _, s := range subjects {
				for _, ref := range t.direct {
					if ref.Type != s.Type || ref.Relation != s.Relation {
						continue
					}
					switch {
					case s.Type == UserType && s.Relation == "":
						isEveryone := s.ID == everyoneID
						if (ref.Wildcard && isEveryone) || (!ref.Wildcard && !isEveryone && s.ID == uid && uid != 0) {
							return true, []string{here + "  <-  " + s.String()}, nil
						}
					case s.Relation != "" && hops > 0:
						ok, sub, err := e.eval(ctx, uid, Object{Type: s.Type, ID: s.ID}, s.Relation, hops-1)
						if err != nil {
							return false, nil, err
						}
						if ok {
							return true, append([]string{here + "  <-  " + s.String()}, sub...), nil
						}
					}
				}
			}

		case termComputed:
			ok, sub, err := e.eval(ctx, uid, obj, t.computed, hops)
			if err != nil {
				return false, nil, err
			}
			if ok {
				return true, append([]string{here + "  <-  " + t.computed}, sub...), nil
			}

		case termFrom:
			if hops == 0 {
				return false, nil, nil
			}
			if e.model.isImplicitSystem(obj.Type, t) {
				ok, sub, err := e.eval(ctx, uid, System, t.rel, hops-1)
				if err != nil || !ok {
					return false, nil, err
				}
				return true, append([]string{fmt.Sprintf("%s  <-  %s from system", here, t.rel)}, sub...), nil
			}
			from, _ := e.model.relation(obj.Type, t.from)
			parents, err := e.subjects(ctx, obj, t.from)
			if err != nil {
				return false, nil, err
			}
			for _, p := range parents {
				allowedParent := false
				for _, ref := range from.directRefs() {
					allowedParent = allowedParent || (ref.Type == p.Type && p.Relation == "")
				}
				if _, defines := e.model.relation(p.Type, t.rel); !allowedParent || !defines {
					continue
				}
				ok, sub, err := e.eval(ctx, uid, Object{Type: p.Type, ID: p.ID}, t.rel, hops-1)
				if err != nil {
					return false, nil, err
				}
				if ok {
					return true, append([]string{fmt.Sprintf("%s  <-  %s from %s (%s)", here, t.rel, t.from, p)}, sub...), nil
				}
			}
		}
	}
	return false, nil, nil
}

// subjects returns everything that directly has rel to obj, from the business
// table column if the relation is column-backed, else from authz_tuples.
func (e *Engine) subjects(ctx context.Context, obj Object, rel string) ([]Ref, error) {
	db := e.conn(ctx)
	if col, ok := e.columns[relKey{obj.Type, rel}]; ok {
		var ids []uint64
		err := db.Table(col.Table).Where(col.IDColumn+" = ?", obj.ID).Pluck(col.SubjectColumn, &ids).Error
		if err != nil {
			return nil, err
		}
		out := make([]Ref, 0, len(ids))
		for _, id := range ids {
			if id != 0 {
				out = append(out, Ref{Type: col.SubjectType, ID: id})
			}
		}
		return out, nil
	}
	var rows []TupleRow
	err := db.Where("object_type = ? AND object_id = ? AND relation = ?", obj.Type, obj.ID, rel).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]Ref, 0, len(rows))
	for _, r := range rows {
		out = append(out, Ref{Type: r.SubjectType, ID: r.SubjectID, Relation: r.SubjectRelation})
	}
	return out, nil
}
