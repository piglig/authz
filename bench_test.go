package authz_test

import (
	"context"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"

	"gorm.io/gorm"

	"github.com/piglig/authz"
)

// Benchmarks of the engine on realistic data. They do not run in `go test`
// run them explicitly (results: README.md):
//
//	go test -run '^$' -bench . -benchtime 200x .
//	AUTHZ_BENCH_SIZE=100000 go test -run '^$' -bench . -benchtime 100x .
//	(SQLite, pure-Go driver. Other databases: run the same benchmarks from an application that uses them.)
//
// Two scenarios, N resources each (AUTHZ_BENCH_SIZE, default 10 000):
//
//	template  the shipped todo + team models: owner column, sharing with
//	          users and teams. No nesting, so the hop limit does not matter.
//	          users N/10, teams N/100 (owner + 5 members), 30% of the
//	          todos shared with a user or a team.
//	nested    the worst case of the test model: teams in teams (20%),
//	          folders N/10 in trees up to 8 levels deep (1% public), docs
//	          in folders, half of the folders and 30% of the docs shared.
//	          Every relation is expanded up to the hop limit (10).

// templateModel mirrors the todo and team models of github.com/piglig/go-ai-starter
// (owner column, sharing with users and teams).
const templateModel = `
type team
  relations
    define owner: [user]
    define member: [user] or owner

type todo
  relations
    define owner: [user]
    define editor: [user, team#member] or owner
    define viewer: [user, team#member] or editor
    define can_read: viewer
`

type benchTodo struct {
	ID     uint64 `gorm:"primaryKey;autoIncrement:false"`
	UserID uint64 `gorm:"index"`
}

type benchTeam struct {
	ID      uint64 `gorm:"primaryKey;autoIncrement:false"`
	OwnerID uint64 `gorm:"index"`
}

type benchSet struct {
	name     string
	e        *authz.Engine
	db       *gorm.DB
	typ      string // resource type: todo | doc
	rel      string // relation checked
	table    string
	users, n int
	ownerOf  []uint64 // resource -> owner
	deep     []uint64 // nested: docs in the deepest folder
}

func benchSize() int {
	if n, err := strconv.Atoi(os.Getenv("AUTHZ_BENCH_SIZE")); err == nil && n >= 100 {
		return n
	}
	return 10_000
}

type tupleSet struct {
	rows []authz.TupleRow
	seen map[authz.TupleRow]bool
}

func (t *tupleSet) add(objType string, objID uint64, rel, subjType string, subjID uint64, subjRel string) {
	row := authz.TupleRow{ObjectType: objType, ObjectID: objID, Relation: rel,
		SubjectType: subjType, SubjectID: subjID, SubjectRelation: subjRel}
	if t.seen == nil {
		t.seen = map[authz.TupleRow]bool{}
	}
	if !t.seen[row] {
		t.seen[row] = true
		t.rows = append(t.rows, row)
	}
}

func buildTemplate(b *testing.B) *benchSet {
	b.Helper()
	n := benchSize()
	_, db := setup(b)
	must(b, db.Migrator().CreateTable(&benchTodo{}, &benchTeam{}))
	e, err := authz.New(db, []authz.Module{{Name: "bench", Model: []byte(templateModel), Columns: []authz.Column{
		{ObjectType: "todo", Relation: "owner", Table: "bench_todos", IDColumn: "id", SubjectType: authz.UserType, SubjectColumn: "user_id"},
		{ObjectType: "team", Relation: "owner", Table: "bench_teams", IDColumn: "id", SubjectType: authz.UserType, SubjectColumn: "owner_id"},
	}}})
	must(b, err)
	rng := rand.New(rand.NewPCG(1, 2))
	s := &benchSet{name: "template", e: e, db: db, typ: "todo", rel: "can_read", table: "bench_todos", users: n / 10, n: n}
	teams := n / 100
	user := func() uint64 { return uint64(rng.IntN(s.users) + 1) }
	var ts tupleSet
	teamRows := make([]benchTeam, 0, teams)
	for t := 1; t <= teams; t++ {
		teamRows = append(teamRows, benchTeam{ID: uint64(t), OwnerID: user()})
		for range 5 {
			ts.add("team", uint64(t), "member", "user", user(), "")
		}
	}
	todos := make([]benchTodo, 0, n)
	for i := 1; i <= n; i++ {
		owner := user()
		todos = append(todos, benchTodo{ID: uint64(i), UserID: owner})
		s.ownerOf = append(s.ownerOf, owner)
		switch rng.IntN(10) {
		case 0, 1:
			ts.add("todo", uint64(i), "viewer", "user", user(), "")
		case 2:
			ts.add("todo", uint64(i), "editor", "team", uint64(rng.IntN(teams)+1), "member")
		}
	}
	must(b, db.CreateInBatches(teamRows, 500).Error)
	must(b, db.CreateInBatches(todos, 500).Error)
	must(b, db.CreateInBatches(ts.rows, 500).Error)
	b.Logf("template: %d todos, %d teams, %d users, %d tuples", n, teams, s.users, len(ts.rows))
	return s
}

func buildNested(b *testing.B) *benchSet {
	b.Helper()
	n := benchSize()
	e, db := setup(b)
	rng := rand.New(rand.NewPCG(1, 2))
	s := &benchSet{name: "nested", e: e, db: db, typ: "doc", rel: "viewer", table: "docs", users: n / 10, n: n}
	folders, teams := n/10, n/100
	user := func() uint64 { return uint64(rng.IntN(s.users) + 1) }
	var ts tupleSet
	for t := 1; t <= teams; t++ {
		for range 5 {
			ts.add("team", uint64(t), "member", "user", user(), "")
		}
		if t > 1 && rng.IntN(5) == 0 {
			ts.add("team", uint64(rng.IntN(t-1)+1), "member", "team", uint64(t), "member")
		}
	}
	depth := make([]int, folders+1)
	maxDepth, deepest := 0, uint64(0)
	for f := 1; f <= folders; f++ {
		if f > 1 && rng.IntN(10) != 0 {
			if p := rng.IntN(f-1) + 1; depth[p] < 7 {
				depth[f] = depth[p] + 1
				ts.add("folder", uint64(f), "parent", "folder", uint64(p), "")
			}
		}
		if depth[f] > maxDepth {
			maxDepth, deepest = depth[f], uint64(f)
		}
		ts.add("folder", uint64(f), "owner", "user", user(), "")
		switch rng.IntN(6) {
		case 0, 1:
			ts.add("folder", uint64(f), "viewer", "user", user(), "")
		case 2:
			ts.add("folder", uint64(f), "editor", "team", uint64(rng.IntN(teams)+1), "member")
		}
		if rng.IntN(100) == 0 {
			ts.add("folder", uint64(f), "viewer", "user", 0, "")
		}
	}
	rows := make([]doc, 0, n)
	for d := 1; d <= n; d++ {
		row := doc{ID: uint64(d), OwnerID: user()}
		if rng.IntN(10) != 0 {
			row.FolderID = uint64(rng.IntN(folders) + 1)
			if row.FolderID == deepest {
				s.deep = append(s.deep, row.ID)
			}
		}
		rows = append(rows, row)
		s.ownerOf = append(s.ownerOf, row.OwnerID)
		if rng.IntN(10) < 3 {
			if rng.IntN(2) == 0 {
				ts.add("doc", uint64(d), "viewer", "user", user(), "")
			} else {
				ts.add("doc", uint64(d), "editor", "team", uint64(rng.IntN(teams)+1), "member")
			}
		}
	}
	must(b, db.CreateInBatches(rows, 500).Error)
	must(b, db.CreateInBatches(ts.rows, 500).Error)
	must(b, db.Exec("CREATE INDEX idx_docs_owner ON docs(owner_id)").Error)
	must(b, db.Exec("CREATE INDEX idx_docs_folder ON docs(folder_id)").Error)
	b.Logf("nested: %d docs, %d folders (max depth %d), %d teams, %d users, %d tuples",
		n, folders, maxDepth, teams, s.users, len(ts.rows))
	return s
}

func BenchmarkCheck(b *testing.B) {
	for _, build := range []func(*testing.B) *benchSet{buildTemplate, buildNested} {
		s := build(b)
		ctx := context.Background()
		rng := rand.New(rand.NewPCG(3, 4))
		cases := []struct {
			name string
			pick func() (uint64, uint64)
		}{
			{"owner", func() (uint64, uint64) { i := rng.IntN(s.n); return s.ownerOf[i], uint64(i + 1) }},
			{"other-user", func() (uint64, uint64) { return uint64(rng.IntN(s.users) + 1), uint64(rng.IntN(s.n) + 1) }},
		}
		if len(s.deep) > 0 {
			cases = append(cases, struct {
				name string
				pick func() (uint64, uint64)
			}{"deepest-folder", func() (uint64, uint64) { return uint64(rng.IntN(s.users) + 1), s.deep[rng.IntN(len(s.deep))] }})
		}
		for _, c := range cases {
			b.Run(s.name+"/"+c.name, func(b *testing.B) {
				allowed := 0
				for b.Loop() {
					uid, id := c.pick()
					d, err := s.e.Check(ctx, authz.Subject{UserID: uid}, s.rel, authz.Object{Type: s.typ, ID: id})
					if err != nil {
						b.Fatal(err)
					}
					if d.Allowed {
						allowed++
					}
				}
				b.ReportMetric(float64(allowed)/float64(b.N), "allowed/op")
			})
		}
	}
}

// BenchmarkFilter measures a list endpoint: the scope plus the page query
// (20 newest visible rows) or the total count.
func BenchmarkFilter(b *testing.B) {
	for _, build := range []func(*testing.B) *benchSet{buildTemplate, buildNested} {
		s := build(b)
		ctx := context.Background()
		rng := rand.New(rand.NewPCG(5, 6))
		for _, q := range []string{"page", "count"} {
			b.Run(s.name+"/"+q, func(b *testing.B) {
				var rows int64
				for b.Loop() {
					scope, err := s.e.Filter(ctx, authz.Subject{UserID: uint64(rng.IntN(s.users) + 1)}, s.rel, s.typ)
					if err != nil {
						b.Fatal(err)
					}
					tx := scope.Apply(s.db.Table(s.table), s.table+".id")
					if q == "count" {
						var n int64
						must(b, tx.Count(&n).Error)
						rows += n
					} else {
						var ids []uint64
						must(b, tx.Order(s.table+".id DESC").Limit(20).Pluck(s.table+".id", &ids).Error)
						rows += int64(len(ids))
					}
				}
				b.ReportMetric(float64(rows)/float64(b.N), "rows/op")
			})
		}
	}
}
