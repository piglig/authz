package authz_test

import (
	"path/filepath"

	"context"
	"errors"
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm/logger"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/piglig/authz"
)

// A model that uses every supported feature: nested teams, folders in
// folders, inheritance from a parent, the user:* wildcard, relations stored
// in business-table columns (doc.owner, doc.parent), application-wide roles
// ("X from system", "extend type system") and intersections ("and").
const testModel = `
extend type system
  relations
    define moderator: [user] or admin

type team
  relations
    define member: [user, team#member]

type folder
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, user:*, team#member] or editor or viewer from parent or moderator from system

type doc
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, user:*, team#member] or editor or viewer from parent
    define reviewer: [user, team#member]
    define can_delete: owner or admin from system
    define can_approve: reviewer and editor
    define can_audit: viewer and moderator from system
    define can_purge: admin from system and moderator from system
`

var testColumns = []authz.Column{
	{ObjectType: "doc", Relation: "owner", Table: "docs", IDColumn: "id", SubjectType: "user", SubjectColumn: "owner_id"},
	{ObjectType: "doc", Relation: "parent", Table: "docs", IDColumn: "id", SubjectType: "folder", SubjectColumn: "folder_id"},
}

type doc struct {
	ID       uint64 `gorm:"primaryKey;autoIncrement:false"`
	OwnerID  uint64
	FolderID uint64
}

func setup(t testing.TB, opts ...authz.Option) (*authz.Engine, *gorm.DB) {
	t.Helper()
	db := openDB(t)
	must(t, authz.Migrate(db))
	must(t, db.Migrator().CreateTable(&doc{}))
	opts = append([]authz.Option{authz.WithConn(txConn)}, opts...)
	e, err := authz.New(db, []authz.Module{{Name: "test", Model: []byte(testModel), Columns: testColumns}}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return e, db
}

// openDB opens a fresh SQLite database (pure Go, no CGO) for one test.
func openDB(t testing.TB) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "authz.db")) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1) // SQLite: one writer; keeps transactions simple
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// txKey carries a transaction in the context, the way applications do; the
// engine finds it through WithConn.
type txKey struct{}

func withTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

func txConn(ctx context.Context, db *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return db.WithContext(ctx)
}

func obj(typ string, id uint64) authz.Object { return authz.Object{Type: typ, ID: id} }
func user(id uint64) authz.Subject           { return authz.Subject{UserID: id} }

func allowed(t *testing.T, e *authz.Engine, uid uint64, rel string, o authz.Object) bool {
	t.Helper()
	d, err := e.Check(context.Background(), user(uid), rel, o)
	if err != nil {
		t.Fatal(err)
	}
	return d.Allowed
}

func TestCheck(t *testing.T) {
	e, db := setup(t)
	ctx := context.Background()
	const alice, bob, carol, dave = 1, 2, 3, 4

	// folder 1 (owner alice) contains folder 2, which contains doc 10 (owner bob, a column).
	must(t, e.Write(ctx, obj("folder", 1), "owner", authz.User(alice)))
	must(t, e.Write(ctx, obj("folder", 2), "parent", authz.ObjectRef(obj("folder", 1))))
	must(t, db.Create(&doc{ID: 10, OwnerID: bob, FolderID: 2}).Error)
	must(t, db.Create(&doc{ID: 11, OwnerID: bob}).Error)
	// carol is in team 5, team 5 is nested in team 6, team 6 may view folder 2.
	must(t, e.Write(ctx, obj("team", 5), "member", authz.User(carol)))
	must(t, e.Write(ctx, obj("team", 6), "member", authz.Userset("team", 5, "member")))
	must(t, e.Write(ctx, obj("folder", 2), "viewer", authz.Userset("team", 6, "member")))
	must(t, e.Write(ctx, obj("folder", 2), "viewer", authz.Userset("team", 6, "member"))) // idempotent

	cases := []struct {
		uid  uint64
		rel  string
		o    authz.Object
		want bool
		why  string
	}{
		{bob, "owner", obj("doc", 10), true, "owner from the business column"},
		{bob, "can_delete", obj("doc", 10), true, "computed from owner"},
		{bob, "viewer", obj("doc", 10), true, "owner -> editor -> viewer"},
		{alice, "editor", obj("doc", 10), true, "owner of the grandparent folder"},
		{alice, "can_delete", obj("doc", 10), false, "ownership is not inherited"},
		{carol, "viewer", obj("doc", 10), true, "nested team -> folder viewer -> inherited"},
		{carol, "editor", obj("doc", 10), false, "viewer only"},
		{carol, "viewer", obj("doc", 11), false, "doc 11 is in no folder"},
		{dave, "viewer", obj("doc", 10), false, "unrelated"},
		{0, "viewer", obj("doc", 10), false, "anonymous"},
		{alice, "viewer", obj("doc", 999), false, "missing object"},
		{dave, "can_delete", obj("doc", 10), false, "dave is neither owner nor admin yet"},
	}
	for _, c := range cases {
		if got := allowed(t, e, c.uid, c.rel, c.o); got != c.want {
			t.Errorf("user %d %s %s = %v, want %v (%s)", c.uid, c.rel, c.o, got, c.want, c.why)
		}
	}

	// user:* makes it public, anonymous callers included.
	must(t, e.Write(ctx, obj("doc", 11), "viewer", authz.Everyone()))
	if !allowed(t, e, 0, "viewer", obj("doc", 11)) || !allowed(t, e, dave, "viewer", obj("doc", 11)) {
		t.Error("a user:* viewer must make the doc readable by everyone")
	}
	if allowed(t, e, 0, "editor", obj("doc", 11)) {
		t.Error("the wildcard grants viewer only")
	}

	// Changes take effect immediately.
	must(t, e.Delete(ctx, obj("team", 5), "member", authz.User(carol)))
	if allowed(t, e, carol, "viewer", obj("doc", 10)) {
		t.Error("leaving the team must revoke inherited access at once")
	}
	must(t, db.Model(&doc{}).Where("id = ?", 10).Update("owner_id", dave).Error)
	if allowed(t, e, bob, "owner", obj("doc", 10)) || !allowed(t, e, dave, "owner", obj("doc", 10)) {
		t.Error("ownership follows the business column")
	}

	// Related: any relation at all.
	if r, _ := e.Related(ctx, user(alice), obj("doc", 10)); !r {
		t.Error("alice is related to doc 10 through the folder")
	}
	if r, _ := e.Related(ctx, user(carol), obj("doc", 10)); r {
		t.Error("carol is no longer related to doc 10")
	}

	// DeleteObject removes tuples where the object appears on either side.
	must(t, e.DeleteObject(ctx, obj("team", 6)))
	rows, _ := e.Tuples(ctx, obj("folder", 2))
	for _, r := range rows {
		if r.SubjectType == "team" && r.SubjectID == 6 {
			t.Error("DeleteObject must remove tuples that use the object as subject")
		}
	}
}

func TestWriteIsValidatedAgainstTheModel(t *testing.T) {
	e, _ := setup(t)
	ctx := context.Background()
	bad := []struct {
		o   authz.Object
		rel string
		s   authz.Ref
		why string
	}{
		{obj("doc", 1), "owner", authz.User(1), "column-backed relation"},
		{obj("doc", 1), "can_delete", authz.User(1), "computed relation accepts no tuples"},
		{obj("doc", 1), "nope", authz.User(1), "unknown relation"},
		{obj("ghost", 1), "viewer", authz.User(1), "unknown type"},
		{obj("folder", 1), "owner", authz.Userset("team", 1, "member"), "owner allows users only"},
		{obj("folder", 1), "owner", authz.Everyone(), "wildcard not allowed on owner"},
		{obj("folder", 1), "parent", authz.User(1), "parent must be a folder"},
		{obj("folder", 0), "viewer", authz.User(1), "zero object id"},
	}
	for _, c := range bad {
		if err := e.Write(ctx, c.o, c.rel, c.s); err == nil {
			t.Errorf("Write(%s#%s@%s) must fail: %s", c.o, c.rel, c.s, c.why)
		}
	}
}

// TestCheckFilterAndExplainAgree is the correctness guarantee of the engine.
// On random relationship graphs, for every user, type and relation:
//
//	Filter (SQL, unbound)  ==  Check on each object (SQL, bound)  ==  Explain (naive walk)
//
// It runs with a small hop limit too, so the bound itself is compared.
func TestCheckFilterAndExplainAgree(t *testing.T) {
	for _, hops := range []int{2, authz.DefaultMaxHops} {
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			e, db := setup(t, authz.WithMaxHops(hops))
			ctx := context.Background()
			rng := rand.New(rand.NewPCG(uint64(hops), 42))
			const users, teams, folders, docs = 5, 4, 5, 8

			for round := range propertyRounds() {
				must(t, db.Exec("DELETE FROM authz_tuples").Error)
				must(t, db.Exec("DELETE FROM docs").Error)
				n := func(max int) uint64 { return uint64(rng.IntN(max) + 1) }

				for range 6 { // team membership, including nesting and cycles
					if rng.IntN(2) == 0 {
						must(t, e.Write(ctx, obj("team", n(teams)), "member", authz.User(n(users))))
					} else {
						must(t, e.Write(ctx, obj("team", n(teams)), "member", authz.Userset("team", n(teams), "member")))
					}
				}
				for f := uint64(1); f <= folders; f++ { // folder tree (may contain cycles)
					if rng.IntN(3) > 0 {
						must(t, e.Write(ctx, obj("folder", f), "parent", authz.ObjectRef(obj("folder", n(folders)))))
					}
				}
				for range 8 {
					rel := []string{"owner", "editor", "viewer"}[rng.IntN(3)]
					var s authz.Ref
					switch k := rng.IntN(6); {
					case rel == "owner" || k < 3:
						s = authz.User(n(users))
					case rel == "viewer" && k == 3:
						s = authz.Everyone()
					default:
						s = authz.Userset("team", n(teams), "member")
					}
					must(t, e.Write(ctx, obj("folder", n(folders)), rel, s))
				}
				for uid := uint64(1); uid <= users; uid++ { // roles
					switch rng.IntN(6) {
					case 0:
						must(t, e.GrantAdmin(ctx, uid))
					case 1:
						must(t, e.GrantRole(ctx, "moderator", uid))
					}
				}
				for d := uint64(1); d <= docs; d++ {
					row := doc{ID: d, OwnerID: n(users)}
					if rng.IntN(3) > 0 {
						row.FolderID = n(folders)
					}
					must(t, db.Create(&row).Error)
					if rng.IntN(3) == 0 {
						must(t, e.Write(ctx, obj("doc", d), "viewer", authz.Userset("team", n(teams), "member")))
					}
					if rng.IntN(8) == 0 {
						must(t, e.Write(ctx, obj("doc", d), "viewer", authz.Everyone()))
					}
					if rng.IntN(2) == 0 {
						must(t, e.Write(ctx, obj("doc", d), "reviewer", authz.User(n(users))))
					}
					if rng.IntN(3) == 0 {
						must(t, e.Write(ctx, obj("doc", d), "editor", authz.User(n(users))))
					}
				}

				count := map[string]uint64{"team": teams, "folder": folders, "doc": docs}
				relations := map[string][]string{
					"team":   {"member"},
					"folder": {"owner", "editor", "viewer"},
					"doc":    {"owner", "editor", "viewer", "reviewer", "can_delete", "can_approve", "can_audit", "can_purge"},
				}
				for typ, rels := range relations {
					for _, rel := range rels {
						for uid := uint64(0); uid <= users; uid++ {
							var viaCheck, viaExplain []uint64
							for id := uint64(1); id <= count[typ]; id++ {
								if allowed(t, e, uid, rel, obj(typ, id)) {
									viaCheck = append(viaCheck, id)
								}
								ok, path, err := e.Explain(ctx, user(uid), rel, obj(typ, id))
								must(t, err)
								if ok {
									viaExplain = append(viaExplain, id)
									if len(path) == 0 {
										t.Fatalf("Explain allowed %s without a path", obj(typ, id))
									}
								}
							}
							viaFilter := filterIDs(t, e, db, uid, rel, typ, count[typ])
							if !slices.Equal(viaCheck, viaExplain) || !slices.Equal(viaCheck, viaFilter) {
								t.Fatalf("round %d: user %d %s#%s disagree\n  check:   %v\n  explain: %v\n  filter:  %v",
									round, uid, typ, rel, viaCheck, viaExplain, viaFilter)
							}
						}
					}
				}
			}
		})
	}
}

// filterIDs applies a Scope to a list of candidate IDs (the docs table for
// docs, a values table otherwise).
func filterIDs(t *testing.T, e *authz.Engine, db *gorm.DB, uid uint64, rel, typ string, n uint64) []uint64 {
	t.Helper()
	scope, err := e.Filter(context.Background(), user(uid), rel, typ)
	must(t, err)
	var ids []uint64
	if typ == "doc" {
		must(t, scope.Apply(db.Model(&doc{}), "docs.id").Order("id").Pluck("id", &ids).Error)
		return ids
	}
	// No business table for teams and folders in this test: probe each ID.
	for id := uint64(1); id <= n; id++ {
		must(t, db.Create(&doc{ID: 1000 + id}).Error)
	}
	var hits []uint64
	must(t, scope.Apply(db.Model(&doc{}).Where("id > 1000"), "(docs.id - 1000)").Order("id").Pluck("id", &hits).Error)
	must(t, db.Exec("DELETE FROM docs WHERE id > 1000").Error)
	for _, h := range hits {
		ids = append(ids, h-1000)
	}
	return ids
}

func TestHopLimitStopsDeepChainsAndCycles(t *testing.T) {
	e, _ := setup(t, authz.WithMaxHops(3))
	ctx := context.Background()

	// user 1 -> team 1 -> team 2 -> team 3 -> team 4 -> team 5
	must(t, e.Write(ctx, obj("team", 1), "member", authz.User(1)))
	for i := uint64(2); i <= 5; i++ {
		must(t, e.Write(ctx, obj("team", i), "member", authz.Userset("team", i-1, "member")))
	}
	if !allowed(t, e, 1, "member", obj("team", 4)) {
		t.Error("3 hops are within the limit")
	}
	if allowed(t, e, 1, "member", obj("team", 5)) {
		t.Error("4 hops exceed the limit and must be denied")
	}

	// A cycle must terminate.
	must(t, e.Write(ctx, obj("team", 1), "member", authz.Userset("team", 5, "member")))
	if allowed(t, e, 2, "member", obj("team", 3)) {
		t.Error("user 2 is in no team")
	}
}

func TestExplainShowsThePath(t *testing.T) {
	e, db := setup(t)
	ctx := context.Background()
	must(t, db.Create(&doc{ID: 1, OwnerID: 9, FolderID: 3}).Error)
	must(t, e.Write(ctx, obj("team", 7), "member", authz.User(1)))
	must(t, e.Write(ctx, obj("folder", 3), "editor", authz.Userset("team", 7, "member")))

	ok, path, err := e.Explain(ctx, user(1), "viewer", obj("doc", 1))
	must(t, err)
	joined := strings.Join(path, "\n")
	for _, want := range []string{"doc:1#viewer", "editor from parent (folder:3)", "team:7#member", "user:1"} {
		if !ok || !strings.Contains(joined, want) {
			t.Fatalf("explanation is missing %q:\n%s", want, joined)
		}
	}
	if ok, path, _ := e.Explain(ctx, user(2), "viewer", obj("doc", 1)); ok || path != nil {
		t.Fatalf("a denied decision has no path, got %v", path)
	}
}

func TestWritesJoinTheTransaction(t *testing.T) {
	e, db := setup(t)
	ctx := context.Background()
	rollback := errors.New("rollback")
	err := db.Transaction(func(tx *gorm.DB) error {
		ctx := withTx(ctx, tx)
		must(t, e.Write(ctx, obj("folder", 1), "owner", authz.User(1)))
		if !allowed2(ctx, t, e, 1, "owner", obj("folder", 1)) {
			t.Error("a check inside the transaction must see its own writes")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if allowed(t, e, 1, "owner", obj("folder", 1)) {
		t.Fatal("a tuple written in a rolled-back transaction must not exist")
	}
}

func allowed2(ctx context.Context, t *testing.T, e *authz.Engine, uid uint64, rel string, o authz.Object) bool {
	t.Helper()
	d, err := e.Check(ctx, user(uid), rel, o)
	must(t, err)
	return d.Allowed
}

func TestModelErrors(t *testing.T) {
	_, db := setup(t)
	bad := map[string]string{
		"exclusion":           "type a\n  relations\n    define x: [user] but not y\n    define y: [user]",
		"condition":           "type a\n  relations\n    define x: [user with ip]",
		"unknown type":        "type a\n  relations\n    define x: [ghost]",
		"unknown userset":     "type a\n  relations\n    define x: [a#nope]",
		"undefined computed":  "type a\n  relations\n    define x: y",
		"computed cycle":      "type a\n  relations\n    define x: y\n    define y: x",
		"from non-direct":     "type a\n  relations\n    define p: x\n    define x: [user] or x from p",
		"from without target": "type a\n  relations\n    define p: [user]\n    define x: x from p",
		"non-user wildcard":   "type a\n  relations\n    define x: [a:*]",
		"duplicate relation":  "type a\n  relations\n    define x: [user]\n    define x: [user]",
		"redefines user":      "type user",
		"mixed and/or":        "type a\n  relations\n    define x: [user]\n    define y: [user]\n    define z: x and y or x",
		"undefined role":      "type a\n  relations\n    define x: [user] or ghost from system",
		"reserved name":       "type a\n  relations\n    define system: [user]",
		"extend non-system":   "extend type a\n  relations\n    define x: [user]",
		"duplicate role":      "extend type system\n  relations\n    define admin: [user]",
		"system from system":  "extend type system\n  relations\n    define x: admin from system",
	}
	for name, text := range bad {
		if _, err := authz.New(db, []authz.Module{{Name: "m", Model: []byte(text)}}); err == nil {
			t.Errorf("%s: New must reject the model", name)
		}
	}
	_, err := authz.New(db, []authz.Module{
		{Name: "m", Model: []byte("type a\n  relations\n    define owner: [user]")},
	}, func(*authz.Engine) {})
	must(t, err)
	_, err = authz.New(db, []authz.Module{{
		Name: "m", Model: []byte("type a\n  relations\n    define owner: [user]"),
		Columns: []authz.Column{{ObjectType: "a", Relation: "owner", Table: "a; DROP", IDColumn: "id", SubjectType: "user", SubjectColumn: "u"}},
	}})
	if err == nil {
		t.Error("a column with an invalid SQL identifier must be rejected")
	}
}

func TestScope(t *testing.T) {
	_, db := setup(t)
	must(t, db.Create(&doc{ID: 1}).Error)

	if _, err := authz.ScopeFrom(context.Background()); !errors.Is(err, authz.ErrNoScope) {
		t.Fatalf("ScopeFrom without a scope must fail loudly, got %v", err)
	}
	if _, err := authz.ScopeFrom(authz.WithScope(context.Background(), authz.Scope{})); !errors.Is(err, authz.ErrNoScope) {
		t.Fatalf("a zero Scope is not a decision, got %v", err)
	}
	var n int64
	must(t, authz.Scope{}.Apply(db.Model(&doc{}), "docs.id").Count(&n).Error)
	if n != 0 {
		t.Fatal("a zero Scope must match nothing")
	}
	must(t, authz.Unrestricted().Apply(db.Model(&doc{}), "docs.id").Count(&n).Error)
	if n != 1 {
		t.Fatal("an unrestricted Scope must match everything")
	}
}

func TestAdminRole(t *testing.T) {
	e, _ := setup(t)
	ctx := context.Background()
	must(t, e.GrantAdmin(ctx, 1))
	if !allowed(t, e, 1, authz.RoleAdmin, authz.System) || allowed(t, e, 2, authz.RoleAdmin, authz.System) {
		t.Fatal("only user 1 is admin")
	}
	must(t, e.RevokeAdmin(ctx, 1))
	if allowed(t, e, 1, authz.RoleAdmin, authz.System) {
		t.Fatal("revoking admin takes effect immediately")
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Rows that bypass Write (a bad migration, manual SQL) must not grant more
// than the model allows: the generator matches only declared subject kinds.
func TestRowsTheModelDoesNotAllowGrantNothing(t *testing.T) {
	e, db := setup(t)
	ctx := context.Background()
	rows := []authz.TupleRow{
		{ObjectType: "folder", ObjectID: 1, Relation: "editor", SubjectType: "user", SubjectID: 0},                           // wildcard on a relation without user:*
		{ObjectType: "folder", ObjectID: 1, Relation: "owner", SubjectType: "team", SubjectID: 1, SubjectRelation: "member"}, // userset on owner
		{ObjectType: "folder", ObjectID: 1, Relation: "parent", SubjectType: "doc", SubjectID: 1},                            // wrong parent type
	}
	must(t, db.Create(&rows).Error)
	must(t, e.Write(ctx, obj("team", 1), "member", authz.User(1)))
	must(t, db.Create(&doc{ID: 1, OwnerID: 1}).Error)

	for _, rel := range []string{"owner", "editor", "viewer"} {
		for _, uid := range []uint64{0, 1, 2} {
			viaExplain, _, err := e.Explain(ctx, user(uid), rel, obj("folder", 1))
			must(t, err)
			if allowed(t, e, uid, rel, obj("folder", 1)) || viaExplain {
				t.Errorf("user %d must not be %s of folder 1 through rows the model does not allow", uid, rel)
			}
		}
	}
}

func TestSystemRolesAndIntersection(t *testing.T) {
	e, db := setup(t)
	ctx := context.Background()
	const owner, admin, moderator, reviewer, editorReviewer = 1, 2, 3, 4, 5
	must(t, db.Create(&doc{ID: 1, OwnerID: owner, FolderID: 7}).Error)
	must(t, db.Create(&doc{ID: 2, OwnerID: owner}).Error)
	must(t, e.GrantAdmin(ctx, admin))
	must(t, e.GrantRole(ctx, "moderator", moderator))
	must(t, e.Write(ctx, obj("doc", 1), "reviewer", authz.User(reviewer)))
	must(t, e.Write(ctx, obj("doc", 1), "reviewer", authz.User(editorReviewer)))
	must(t, e.Write(ctx, obj("doc", 1), "editor", authz.User(editorReviewer)))

	cases := []struct {
		uid  uint64
		rel  string
		o    authz.Object
		want bool
		why  string
	}{
		{admin, "can_delete", obj("doc", 1), true, "admin from system"},
		{admin, "can_delete", obj("doc", 2), true, "admin from system applies to every object"},
		{moderator, "can_delete", obj("doc", 1), false, "moderator is not admin"},
		{admin, "viewer", obj("folder", 7), true, "moderator includes admin; folder viewer includes moderator from system"},
		{admin, "viewer", obj("doc", 1), true, "inherited from the folder through the universal role"},
		{admin, "viewer", obj("doc", 2), false, "doc 2 has no folder, and doc viewer has no system term"},
		{moderator, "viewer", obj("doc", 1), true, "moderator role through the parent folder"},
		{reviewer, "can_approve", obj("doc", 1), false, "reviewer but not editor"},
		{editorReviewer, "can_approve", obj("doc", 1), true, "reviewer and editor"},
		{owner, "can_approve", obj("doc", 1), false, "editor (owner) but not reviewer"},
		{moderator, "can_audit", obj("doc", 1), true, "viewer (via folder) and moderator"},
		{owner, "can_audit", obj("doc", 1), false, "viewer but not moderator"},
		{admin, "can_purge", obj("doc", 2), true, "both conditions are roles: every object"},
		{moderator, "can_purge", obj("doc", 2), false, "moderator but not admin"},
		{0, "can_delete", obj("doc", 1), false, "anonymous"},
	}
	for _, c := range cases {
		if got := allowed(t, e, c.uid, c.rel, c.o); got != c.want {
			t.Errorf("user %d %s %s = %v, want %v (%s)", c.uid, c.rel, c.o, got, c.want, c.why)
		}
		ok, path, err := e.Explain(ctx, user(c.uid), c.rel, c.o)
		must(t, err)
		if ok != c.want || (ok && len(path) == 0) {
			t.Errorf("Explain user %d %s %s = %v %v, want %v", c.uid, c.rel, c.o, ok, path, c.want)
		}
	}

	// A universal role makes the list scope unrestricted.
	scope, err := e.Filter(ctx, user(admin), "can_delete", "doc")
	must(t, err)
	var n int64
	must(t, scope.Apply(db.Model(&doc{}), "docs.id").Count(&n).Error)
	if n != 2 {
		t.Errorf("admin must see every doc through `admin from system`, got %d", n)
	}
	scope, err = e.Filter(ctx, user(owner), "can_delete", "doc")
	must(t, err)
	must(t, scope.Apply(db.Model(&doc{}), "docs.id").Count(&n).Error)
	if n != 2 {
		t.Errorf("the owner owns both docs, got %d", n)
	}

	// Roles are validated and revocable.
	if err := e.GrantRole(ctx, "superhero", 1); err == nil {
		t.Error("granting an undefined role must fail")
	}
	must(t, e.RevokeRole(ctx, "moderator", moderator))
	if allowed(t, e, moderator, "can_audit", obj("doc", 1)) {
		t.Error("revoking a role takes effect immediately")
	}
}

// propertyRounds is how many random graphs the agreement test builds per hop
// limit: one locally, so the definition of done stays fast, and eight in CI
// (TEST_THOROUGH=1). One round still
// exercises every relation; mutations of the generator fail in round 0.
func propertyRounds() int {
	if os.Getenv("TEST_THOROUGH") != "" {
		return 8
	}
	return 1
}

// Only relations that nest are expanded up to the hop limit; the others are
// capped at their static depth, so their cost does not depend on the limit.
func TestStaticDepth(t *testing.T) {
	e, _ := setup(t)
	cases := []struct {
		typ, rel string
		want     int // -1: unbounded (part of, or reaching, a cycle)
	}{
		{"system", "admin", 0},
		{"system", "moderator", 0},
		{"team", "member", -1},   // teams in teams
		{"folder", "owner", 0},   // direct only
		{"folder", "viewer", -1}, // folders in folders
		{"doc", "owner", 0},
		{"doc", "reviewer", -1}, // team#member, which nests
		{"doc", "can_delete", 1},
		{"doc", "can_purge", 1},
		{"doc", "viewer", -1},
	}
	for _, c := range cases {
		if got := e.Depth(c.typ, c.rel); got != c.want {
			t.Errorf("depth(%s#%s) = %d, want %d", c.typ, c.rel, got, c.want)
		}
	}
}

func TestObserverSeesEveryDecision(t *testing.T) {
	var seen []authz.DecisionEvent
	e, db := setup(t, authz.WithObserver(func(_ context.Context, d authz.DecisionEvent) { seen = append(seen, d) }))
	must(t, db.Create(&doc{ID: 1, OwnerID: 7}).Error)
	ctx := context.Background()
	allowed(t, e, 7, "owner", obj("doc", 1))
	allowed(t, e, 8, "owner", obj("doc", 1))
	_, err := e.Filter(ctx, user(7), "viewer", "doc")
	must(t, err)
	if len(seen) != 3 || !seen[0].Allowed || seen[1].Allowed || seen[2].Object != "doc:*" || seen[1].Subject.UserID != 8 {
		t.Fatalf("observed: %+v", seen)
	}
}
