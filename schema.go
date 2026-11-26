package authz

import (
	"time"

	"gorm.io/gorm"
)

// TupleTable is the table holding relationship tuples.
const TupleTable = "authz_tuples"

// tupleSchema is the table definition. Applications that version their
// schema (gormigrate, goose, ...) should copy it into a migration as a
// snapshot instead of calling Migrate, so later library versions never
// change an applied migration.
//
// Indexes:
//
//	uniq_authz_tuple   one row per fact; "does this object have this tuple"
//	idx_authz_reverse  "objects of type T whose relation R is held by one of
//	                   these subjects": every set the engine builds (covering)
//	idx_authz_subject  DeleteObject removes rows whose subject is the object
type tupleSchema struct {
	ID              uint64 `gorm:"primaryKey"`
	ObjectType      string `gorm:"size:64;not null;uniqueIndex:uniq_authz_tuple,priority:1;index:idx_authz_reverse,priority:1"`
	ObjectID        uint64 `gorm:"not null;uniqueIndex:uniq_authz_tuple,priority:2;index:idx_authz_reverse,priority:6"`
	Relation        string `gorm:"size:64;not null;uniqueIndex:uniq_authz_tuple,priority:3;index:idx_authz_reverse,priority:2"`
	SubjectType     string `gorm:"size:64;not null;uniqueIndex:uniq_authz_tuple,priority:4;index:idx_authz_reverse,priority:3;index:idx_authz_subject,priority:1"`
	SubjectID       uint64 `gorm:"not null;uniqueIndex:uniq_authz_tuple,priority:5;index:idx_authz_reverse,priority:5;index:idx_authz_subject,priority:2"`
	SubjectRelation string `gorm:"size:64;not null;default:'';uniqueIndex:uniq_authz_tuple,priority:6;index:idx_authz_reverse,priority:4"`
	CreatedAt       time.Time
}

// Migrate creates the tuple table and its indexes if they do not exist.
func Migrate(db *gorm.DB) error {
	if db.Migrator().HasTable(TupleTable) {
		return nil
	}
	return db.Table(TupleTable).Migrator().CreateTable(&tupleSchema{})
}
