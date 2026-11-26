# authz

Relationship-based authorization (the Zanzibar model) for Go applications on GORM. Relationships live in the application database, next to the business data, and are written in the same transaction. Works on SQLite, MySQL and PostgreSQL: decisions are plain SQL, without recursive queries.

Extracted from [go-ai-starter](https://github.com/piglig/go-ai-starter), which wires it into HTTP routes.

```go
engine, err := authz.New(db, []authz.Module{todoModule, teamModule},
	authz.WithConn(database.Conn),   // join the request's transaction
	authz.WithObserver(logAndCount), // decision log / metrics
	authz.WithMaxHops(10),
)
d, err := engine.Check(ctx, authz.Subject{UserID: 9}, "can_read", authz.Object{Type: "todo", ID: 42}) // d.Allowed
scope, err := engine.Filter(ctx, authz.Subject{UserID: 9}, "can_read", "todo")
db = scope.Apply(db.Model(&Todo{}), "todos.id") // the list a user may see
```

## Model

Each module describes its types in a subset of the [OpenFGA modeling language](https://openfga.dev/docs/configuration-language):

```
extend type system
  relations
    define moderator: [user] or admin

type todo
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, user:*, team#member] or editor or viewer from parent
    define can_read: viewer
    define can_delete: owner or moderator from system
    define can_approve: reviewer and editor
```

| Syntax | Meaning |
|---|---|
| `[user]` | granted to a user directly |
| `[team#member]` | granted to every member of a team |
| `[user:*]` | granted to everyone, including anonymous callers |
| `or owner` | everyone with `owner` has it |
| `editor from parent` | inherited from the parent object |
| `admin from system` | an application-wide role: holders have it on every object |
| `a and b` | both |

A relation is a union or an intersection; to combine them, define a helper relation. `but not`, conditions (`with`) and parentheses are rejected. The model stays monotonic, so a chain cut off by the hop limit can only deny, never grant. Any model error fails `New`.

`type user` and `type system` (with `define admin: [user]`) are built in.

## Relationships

Relations that a business table already stores are declared as columns and read from that table, with nothing to write or clean up:

```go
authz.Module{Name: "todo", Model: model, Columns: []authz.Column{
	{ObjectType: "todo", Relation: "owner", Table: "todos", IDColumn: "id", SubjectType: authz.UserType, SubjectColumn: "user_id"},
}}
```

The others are tuples in `authz_tuples`, validated against the model:

```go
engine.Write(ctx, todo, "viewer", authz.User(7))
engine.Write(ctx, todo, "editor", authz.Userset("team", 3, "member"))
engine.Write(ctx, todo, "viewer", authz.Everyone())
engine.Delete(ctx, todo, "viewer", authz.User(7))
engine.DeleteObject(ctx, todo) // when the todo is deleted
engine.GrantRole(ctx, "moderator", 7)
```

Create the table with `authz.Migrate(db)`, or copy the schema in `schema.go` into your own versioned migration.

## Decisions

- `Check`, `Require` (returns `ErrDenied`), `Related` (any relation at all: tells 403 from 404), `Filter` (a `Scope` for list queries), `Explain` (the chain of facts behind a decision, from a second, naive evaluator).
- Check and Filter come from one SQL generator, so they cannot disagree. A randomized test compares Filter, Check and Explain on graphs with nested teams, folder trees, cycles, wildcards, roles and intersections (`TEST_THOROUGH=1` for eight rounds).
- Only relations that nest (teams in teams, folders in folders) are expanded up to the hop limit; the others are capped at their static depth, so their cost does not depend on it.

## Performance

`go test -run '^$' -bench . .` (SQLite, pure-Go driver, one machine, 2026-11):

| Scenario | Rows | Check | List page (20) |
|---|---|---|---|
| owner + sharing with users and teams, no nesting | 10k / 100k | 0.13 / 0.2 ms | 0.27 / 0.33 ms |
| nested teams + 8-level folder trees, hop limit 10 | 10k / 100k | 14 / 19 ms | 17 / 28 ms |

Index the business-table columns used in `Column` (e.g. `todos.user_id`).

## Status

v0.x: the API may still change. Tested on SQLite here; MySQL and PostgreSQL are exercised by the applications that use it.
