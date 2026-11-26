package authz

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"gorm.io/gorm"
)

// DefaultMaxHops bounds how many relationship hops (into a team, up to a
// parent) one decision may follow. Deeper chains are denied, never looped.
const DefaultMaxHops = 10

// Module is what one application module contributes to the model.
type Module struct {
	Name    string
	Model   []byte   // content of the module's model.fga
	Columns []Column // relations stored as columns of business tables
}

// Column declares that a relation is stored in a business table instead of
// authz_tuples: for every row, the object <ObjectType>:<IDColumn> has
// <Relation> to the subject <SubjectType>:<SubjectColumn>.
//
//	authz.Column{ObjectType: "todo", Relation: "owner", Table: "todos", IDColumn: "id", SubjectType: "user", SubjectColumn: "user_id"}
//	authz.Column{ObjectType: "task", Relation: "parent", Table: "tasks", IDColumn: "id", SubjectType: "project", SubjectColumn: "project_id"}
//
// The business row is the single source of truth, so there is nothing to
// grant on create or clean up on delete. A column-backed relation cannot
// also hold tuples.
type Column struct {
	ObjectType    string
	Relation      string
	Table         string
	IDColumn      string
	SubjectType   string
	SubjectColumn string
}

// Object identifies a resource, e.g. {Type: "todo", ID: 42}.
type Object struct {
	Type string
	ID   uint64
}

func (o Object) String() string { return o.Type + ":" + strconv.FormatUint(o.ID, 10) }

// System is the single object of SystemType; application-wide roles are
// relations on it (see GrantAdmin).
var System = Object{Type: SystemType, ID: 1}

// Subject is the principal asking. UserID 0 is an anonymous caller.
type Subject struct {
	UserID uint64
}

// Anonymous reports whether the subject is not signed in.
func (s Subject) Anonymous() bool { return s.UserID == 0 }

type relKey struct{ typ, rel string }

// Engine evaluates decisions.
type Engine struct {
	connFn  func(ctx context.Context, db *gorm.DB) *gorm.DB
	observe func(ctx context.Context, d DecisionEvent)
	db      *gorm.DB
	model   *Model
	columns map[relKey]Column
	maxHops int
}

// Option customises an Engine.
type Option func(*Engine)

// WithMaxHops overrides DefaultMaxHops.
func WithMaxHops(n int) Option { return func(e *Engine) { e.maxHops = n } }

// WithConn sets how the engine gets its database handle for a request. Pass
// a function that returns the transaction carried by ctx when there is one,
// so that Write / Delete join the caller's transaction and checks inside it
// see its writes. Default: db.WithContext(ctx).
func WithConn(conn func(ctx context.Context, db *gorm.DB) *gorm.DB) Option {
	return func(e *Engine) { e.connFn = conn }
}

// DecisionEvent describes one Check or Filter, for logging and metrics.
type DecisionEvent struct {
	Subject  Subject
	Relation string
	Object   string // "todo:42", or "todo:*" for a Filter
	Allowed  bool
}

// WithObserver is called after every Check and Filter (e.g. to log denials
// and count decisions). It must be fast and must not fail.
func WithObserver(observe func(ctx context.Context, d DecisionEvent)) Option {
	return func(e *Engine) { e.observe = observe }
}

var sqlIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// New builds the engine from every module's model and columns. Any error in
// a model fails startup.
func New(db *gorm.DB, modules []Module, opts ...Option) (*Engine, error) {
	model, err := newModel(modules)
	if err != nil {
		return nil, err
	}
	e := &Engine{db: db, model: model, columns: map[relKey]Column{}, maxHops: DefaultMaxHops}
	for _, opt := range opts {
		opt(e)
	}
	for _, mod := range modules {
		for _, c := range mod.Columns {
			if err := e.addColumn(mod.Name, c); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}

func (e *Engine) addColumn(module string, c Column) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("authz: %s: column for %s#%s: %s", module, c.ObjectType, c.Relation, fmt.Sprintf(format, args...))
	}
	rel, ok := e.model.relation(c.ObjectType, c.Relation)
	if !ok {
		return fail("the model does not define this relation")
	}
	allowed := false
	for _, ref := range rel.directRefs() {
		allowed = allowed || (ref.Type == c.SubjectType && ref.Relation == "" && !ref.Wildcard)
	}
	if !allowed {
		return fail("the relation must directly allow [%s]", c.SubjectType)
	}
	for _, ident := range []string{c.Table, c.IDColumn, c.SubjectColumn} {
		if !sqlIdentRe.MatchString(ident) {
			return fail("invalid SQL identifier %q", ident)
		}
	}
	key := relKey{c.ObjectType, c.Relation}
	if _, dup := e.columns[key]; dup {
		return fail("declared twice")
	}
	e.columns[key] = c
	return nil
}

// HasRelation reports whether the model defines relation on objectType.
func (e *Engine) HasRelation(objectType, relation string) bool {
	_, ok := e.model.relation(objectType, relation)
	return ok
}

// Decision is the outcome of a Check.
type Decision struct {
	Allowed bool
}

// ErrDenied is returned by Require when access is denied.
var ErrDenied = errors.New("authz: denied")

// Check reports whether subject has relation to object.
func (e *Engine) Check(ctx context.Context, subject Subject, relation string, object Object) (Decision, error) {
	if !e.HasRelation(object.Type, relation) {
		return Decision{}, fmt.Errorf("authz: type %q has no relation %q", object.Type, relation)
	}
	g := newSQLGen(e, subject.UserID)
	frags, conds := g.boundOperands(object.Type, relation, e.maxHops, object.ID)
	allowed, err := e.decide(ctx, g, frags, conds)
	if err != nil {
		return Decision{}, fmt.Errorf("authz: check %s %s: %w", relation, object, err)
	}
	e.record(ctx, subject, relation, object.String(), allowed)
	return Decision{Allowed: allowed}, nil
}

// Require is Check that returns ErrDenied when access is denied.
func (e *Engine) Require(ctx context.Context, subject Subject, relation string, object Object) error {
	d, err := e.Check(ctx, subject, relation, object)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return ErrDenied
	}
	return nil
}

// Related reports whether subject has ANY relation to object. Enforcement
// points use it to tell "you may not" (403) from "this does not exist for
// you" (404).
func (e *Engine) Related(ctx context.Context, subject Subject, object Object) (bool, error) {
	t, ok := e.model.types[object.Type]
	if !ok {
		return false, fmt.Errorf("authz: unknown type %q", object.Type)
	}
	g := newSQLGen(e, subject.UserID)
	var frags []frag
	var conds []string
	for _, rel := range t.order {
		f, c := g.boundOperands(object.Type, rel, e.maxHops, object.ID)
		frags, conds = append(frags, f...), append(conds, c...)
	}
	related, err := e.decide(ctx, g, frags, conds)
	if err != nil {
		return false, fmt.Errorf("authz: related %s: %w", object, err)
	}
	return related, nil
}

// decide runs one CASE query: any SELECT returns a row, or any universal
// condition holds.
func (e *Engine) decide(ctx context.Context, g *sqlGen, frags []frag, conds []string) (bool, error) {
	sql, args, ok := g.decision(frags, conds)
	if !ok {
		return false, nil
	}
	var result []int
	if err := e.conn(ctx).Raw(sql, args...).Scan(&result).Error; err != nil {
		return false, err
	}
	return len(result) == 1 && result[0] == 1, nil
}

// Filter returns the Scope of objects of objectType that subject has
// relation to, for use in a list query.
func (e *Engine) Filter(ctx context.Context, subject Subject, relation, objectType string) (Scope, error) {
	if !e.HasRelation(objectType, relation) {
		return Scope{}, fmt.Errorf("authz: type %q has no relation %q", objectType, relation)
	}
	g := newSQLGen(e, subject.UserID)
	top := g.node(objectType, relation, e.maxHops)
	// Universal conditions do not depend on the object: decide them once.
	// When one holds (e.g. the caller is an admin and the model says
	// `admin from system`), every object is visible.
	if len(top.conds) > 0 {
		all, err := e.decide(ctx, g, nil, top.conds)
		if err != nil {
			return Scope{}, fmt.Errorf("authz: filter %s %s: %w", relation, objectType, err)
		}
		if all {
			e.record(ctx, subject, relation, objectType+":*", true)
			return Unrestricted(), nil
		}
	}
	sql, args := g.withDefs("SELECT id FROM "+top.cte, nil)
	e.record(ctx, subject, relation, objectType+":*", true)
	return Scope{kind: scopeSQL, sql: sql, args: args}, nil
}

// record writes the decision log (denials at info, the rest at debug) and
// counts the decision.
func (e *Engine) record(ctx context.Context, subject Subject, relation, object string, allowed bool) {
	if e.observe != nil {
		e.observe(ctx, DecisionEvent{Subject: subject, Relation: relation, Object: object, Allowed: allowed})
	}
}

func (e *Engine) conn(ctx context.Context) *gorm.DB {
	if e.connFn != nil {
		return e.connFn(ctx, e.db)
	}
	return e.db.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

type scopeKind int

const (
	scopeNone scopeKind = iota // zero value: no decision was made
	scopeUnrestricted
	scopeSQL
)

// Scope restricts a list query to the objects a subject may see. Obtain it
// with ScopeFrom on a route registered through httpx.Router; never build one
// by hand.
type Scope struct {
	kind scopeKind
	sql  string
	args []any
}

// Unrestricted is the scope of routes whose access rule does not depend on
// individual objects (httpx.Public, httpx.Authenticated, system-level rules).
func Unrestricted() Scope { return Scope{kind: scopeUnrestricted} }

// Apply adds the scope to a query. idColumn is the object's primary key
// column, e.g. "todos.id". A zero Scope matches nothing.
func (s Scope) Apply(q *gorm.DB, idColumn string) *gorm.DB {
	switch s.kind {
	case scopeUnrestricted:
		return q
	case scopeSQL:
		return q.Where(idColumn+" IN ("+s.sql+")", s.args...)
	}
	return q.Where("1 = 0")
}

type scopeKey struct{}

// WithScope stores the scope computed by a route's enforcement point.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ErrNoScope means a list query ran outside a route registered through
// httpx.Router. Failing loudly is the point: an unscoped list would return
// every row.
var ErrNoScope = errors.New("authz: no list scope in context (register the route through httpx.Router)")

// ScopeFrom returns the scope of the current request.
func ScopeFrom(ctx context.Context) (Scope, error) {
	s, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok || s.kind == scopeNone {
		return Scope{}, ErrNoScope
	}
	return s, nil
}
