package mgoauth

import (
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo/bson"
)

type Group struct {
	Id bson.ObjectId `bson:"_id"`
	auth.Group
}

// GetId returns an bson.ObjectId hex string
func (g *Group) GetId() interface{} {
	return g.Id.Hex()
}

// SetId must recive a valid bson.ObjectId hex string, otherwise an
// ErrInvalidIdHex returned.
func (g *Group) SetId(id interface{}) error {
	sid, ok := id.(string)
	if !ok {
		return auth.ErrInvalidId
	}

	if !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	g.Id = bson.ObjectIdHex(sid)
	return nil
}

type MgoGroupManager struct{}

// AddGroupDetail adds a group with full detail to database.
func (m *MgoGroupManager) AddGroupDetail(name string, info auth.GroupInfo,
	pri map[string]bool) (auth.Grouper, error) {
	panic("not implementd")
}

// UpdateInfo updates group infomation specific by id.
func (m *MgoGroupManager) UpdateInfo(id interface{}, info auth.GroupInfo) error {
	panic("not implementd")
}

// UpdatePrivilege updates group privilege specific by id.
func (m *MgoGroupManager) UpdatePrivilege(id interface{},
	pri map[string]bool) error {
	panic("not implementd")
}

// FindGroup find the group specific by id.
func (m *MgoGroupManager) FindGroup(id interface{}) (auth.Grouper, error) {
	panic("not implementd")
}

// FindSomeGroup find and return a slice of group specific by thier id.
func (m *MgoGroupManager) FindSomeGroup(id ...interface{}) ([]auth.Grouper, error) {
	panic("not implementd")
}

// FindAllGroup finds and return a slice of group. offsetId define which
// sub-sequence of matching groups to be returned.
func (m *MgoGroupManager) FindAllGroup(offsetId interface{}, limit int) (
	[]auth.Grouper, error) {
	panic("not implementd")
}
