package mgoauth

import (
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type MgoGroupManager struct {
	GroupColl *mgo.Collection
}

// AddGroupDetail adds a group with full detail to database.
func (m *MgoGroupManager) AddGroupDetail(name string, info *auth.GroupInfo,
	pri map[string]bool) (*auth.Group, error) {
	group := &auth.Group{}
	group.Name = name
	group.Info = *info
	group.Privilege = pri

	err := m.GroupColl.Insert(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

// UpdateGroupDetail updates group detail specific by id.
func (m *MgoGroupManager) UpdateGroupDetail(id interface{}, info *auth.GroupInfo,
	pri map[string]bool) error {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return auth.ErrInvalidId
	}

	change := bson.M{}
	if info != nil {
		change["info"] = info
	}
	if pri != nil {
		change["privilege"] = pri
	}

	return m.GroupColl.UpdateId(bson.ObjectIdHex(sid), bson.M{"$set": change})
}

// FindGroup find the group specific by id.
func (m *MgoGroupManager) FindGroup(id interface{}) (*auth.Group, error) {
	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return nil, auth.ErrInvalidId
	}

	group := &auth.Group{}
	err := m.GroupColl.FindId(bson.ObjectIdHex(sid)).One(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

// FindSomeGroup find and return a slice of group specific by thier id.
func (m *MgoGroupManager) FindSomeGroup(id ...interface{}) (
	[]*auth.Group, error) {
	aid := make([]bson.ObjectId, 0, len(id))
	for _, v := range id {
		sid, ok := v.(string)
		if !ok || !bson.IsObjectIdHex(sid) {
			continue // ??? should we return error here?
		}
		aid = append(aid, bson.ObjectIdHex(sid))
	}

	if len(aid) == 0 {
		return nil, ErrNoResult
	}

	return nil, nil
}

// FindAllGroup finds and return a slice of group. offsetId define which
// sub-sequence of matching groups to be returned.
func (m *MgoGroupManager) FindAllGroup(offsetId interface{}, limit int) (
	[]*auth.Group, error) {
	if limit < 0 {
		return nil, ErrNoResult
	}

	sid, ok := offsetId.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return nil, auth.ErrInvalidId
	}

	var groups []*auth.Group
	err := m.GroupColl.Find(bson.M{"_id": bson.M{
		"$gt": bson.ObjectIdHex(sid),
	}}).All(&groups)

	if err != nil {
		return nil, err
	}

	return groups, nil

}

var _ auth.GroupManager = &MgoGroupManager{}
