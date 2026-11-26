package authz

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/clause"
)

// everyoneID is the subject ID of the user:* wildcard (real IDs start at 1).
const everyoneID uint64 = 0

// TupleRow is one row of authz_tuples: Subject has Relation to Object.
type TupleRow struct {
	ID              uint64 `gorm:"primaryKey"`
	ObjectType      string `gorm:"size:64;not null"`
	ObjectID        uint64 `gorm:"not null"`
	Relation        string `gorm:"size:64;not null"`
	SubjectType     string `gorm:"size:64;not null"`
	SubjectID       uint64 `gorm:"not null"`
	SubjectRelation string `gorm:"size:64;not null;default:''"`
	CreatedAt       time.Time
}

func (TupleRow) TableName() string { return "authz_tuples" }

// Ref is the subject of a tuple.
type Ref struct {
	Type     string
	ID       uint64
	Relation string // "member" for team:5#member; "" for a plain subject
}

func (r Ref) String() string {
	s := fmt.Sprintf("%s:%d", r.Type, r.ID)
	if r.Type == UserType && r.ID == everyoneID {
		s = UserType + ":*"
	}
	if r.Relation != "" {
		s += "#" + r.Relation
	}
	return s
}

// User is the subject "this user".
func User(id uint64) Ref { return Ref{Type: UserType, ID: id} }

// Userset is the subject "everyone who has relation to that object",
// e.g. Userset("team", 5, "member").
func Userset(objectType string, id uint64, relation string) Ref {
	return Ref{Type: objectType, ID: id, Relation: relation}
}

// ObjectRef is a plain object as subject, e.g. the parent of a task.
func ObjectRef(o Object) Ref { return Ref{Type: o.Type, ID: o.ID} }

// Everyone is the user:* wildcard: every caller, signed in or not. The
// relation must allow [user:*] in the model.
func Everyone() Ref { return Ref{Type: UserType, ID: everyoneID} }

// validate checks a tuple against the model.
func (e *Engine) validate(object Object, relation string, subject Ref) error {
	rel, ok := e.model.relation(object.Type, relation)
	if !ok {
		return fmt.Errorf("authz: type %q has no relation %q", object.Type, relation)
	}
	if _, col := e.columns[relKey{object.Type, relation}]; col {
		return fmt.Errorf("authz: %s#%s is stored in a business table column; change the row instead", object.Type, relation)
	}
	if object.ID == 0 || (subject.ID == 0 && !(subject.Type == UserType && subject.Relation == "")) {
		return fmt.Errorf("authz: tuple %s#%s@%s has a zero ID", object, relation, subject)
	}
	wildcard := subject.Type == UserType && subject.ID == everyoneID && subject.Relation == ""
	for _, ref := range rel.directRefs() {
		if ref.Type == subject.Type && ref.Relation == subject.Relation && ref.Wildcard == wildcard {
			return nil
		}
	}
	return fmt.Errorf("authz: %s#%s does not accept %s as a subject (see the model: it allows %v)",
		object.Type, relation, subject, rel.directRefs())
}

// Write stores the tuple "subject has relation to object". It is idempotent
// and joins the caller's transaction (see WithConn): write it together
// with the business change it belongs to.
func (e *Engine) Write(ctx context.Context, object Object, relation string, subject Ref) error {
	if err := e.validate(object, relation, subject); err != nil {
		return err
	}
	row := &TupleRow{
		ObjectType: object.Type, ObjectID: object.ID, Relation: relation,
		SubjectType: subject.Type, SubjectID: subject.ID, SubjectRelation: subject.Relation,
	}
	if err := e.conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error; err != nil {
		return fmt.Errorf("authz: write %s#%s@%s: %w", object, relation, subject, err)
	}
	return nil
}

// Delete removes one tuple. Deleting a tuple that does not exist is a no-op.
func (e *Engine) Delete(ctx context.Context, object Object, relation string, subject Ref) error {
	err := e.conn(ctx).
		Where("object_type = ? AND object_id = ? AND relation = ? AND subject_type = ? AND subject_id = ? AND subject_relation = ?",
			object.Type, object.ID, relation, subject.Type, subject.ID, subject.Relation).
		Delete(&TupleRow{}).Error
	if err != nil {
		return fmt.Errorf("authz: delete %s#%s@%s: %w", object, relation, subject, err)
	}
	return nil
}

// DeleteObject removes every tuple that mentions object, as object or as
// subject. Call it in the transaction that deletes the business row.
func (e *Engine) DeleteObject(ctx context.Context, object Object) error {
	err := e.conn(ctx).
		Where("(object_type = ? AND object_id = ?) OR (subject_type = ? AND subject_id = ?)",
			object.Type, object.ID, object.Type, object.ID).
		Delete(&TupleRow{}).Error
	if err != nil {
		return fmt.Errorf("authz: delete tuples of %s: %w", object, err)
	}
	return nil
}

// Tuples lists the stored tuples of object (e.g. for a sharing screen).
// Column-backed relations are not included.
func (e *Engine) Tuples(ctx context.Context, object Object) ([]TupleRow, error) {
	var rows []TupleRow
	err := e.conn(ctx).
		Where("object_type = ? AND object_id = ?", object.Type, object.ID).
		Order("id").Find(&rows).Error
	return rows, err
}

// GrantRole gives the user an application-wide role: a relation on the
// system object (RoleAdmin, or one added with `extend type system`).
// Idempotent.
func (e *Engine) GrantRole(ctx context.Context, role string, userID uint64) error {
	return e.Write(ctx, System, role, User(userID))
}

// RevokeRole removes an application-wide role.
func (e *Engine) RevokeRole(ctx context.Context, role string, userID uint64) error {
	return e.Delete(ctx, System, role, User(userID))
}

// GrantAdmin gives the user the built-in admin role. Idempotent.
func (e *Engine) GrantAdmin(ctx context.Context, userID uint64) error {
	return e.GrantRole(ctx, RoleAdmin, userID)
}

// RevokeAdmin removes the built-in admin role.
func (e *Engine) RevokeAdmin(ctx context.Context, userID uint64) error {
	return e.RevokeRole(ctx, RoleAdmin, userID)
}
