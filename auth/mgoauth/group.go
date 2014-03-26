package mgoauth

import (
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type MgoGroupManager struct {
	GroupColl *mgo.Collection
}

func NewMgoGroupManager(db *mgo.Database) *MgoGroupManager {
	return &MgoGroupManager{db.C("mgoauth_group")}
}

// AddGroupDetail adds a group with full detail to database.
func (m *MgoGroupManager) AddGroupDetail(name string, info *auth.GroupInfo,
	pri map[string]bool) (*auth.Group, error) {
	group := &auth.Group{}
	group.Id = bson.NewObjectId()
	group.Name = name
	group.Info = *info
	group.Privilege = pri

	err := m.GroupColl.Insert(group)
	if err != nil {
		if mgo.IsDup(err) {
			return nil, auth.ErrDuplicateName
		}
		return nil, err
	}

	return group, nil
}

// UpdateGroupDetail updates group detail specific by id.
func (m *MgoGroupManager) UpdateGroupDetail(id interface{}, info *auth.GroupInfo,
	pri map[string]bool) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	change := bson.M{}
	if info != nil {
		change["info"] = info
	}
	if pri != nil {
		change["privilege"] = pri
	}

	return m.GroupColl.UpdateId(oid, bson.M{"$set": change})
}

// FindGroup find the group specific by id.
func (m *MgoGroupManager) FindGroup(id interface{}) (*auth.Group, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	group := &auth.Group{}
	err = m.GroupColl.FindId(oid).One(group)
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
		oid, err := getId(v)
		if err != nil {
			continue
		}
		aid = append(aid, oid)
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
	if limit == 0 {
		return nil, ErrNoResult
	}

	filter := bson.M{}
	oid, err := getId(offsetId)
	if err == nil {
		filter["_id"] = bson.M{"$gt": oid}
	}

	query := m.GroupColl.Find(filter)
	var groups []*auth.Group
	if limit > 0 {
		query.Limit(limit)
		groups = make([]*auth.Group, 0, limit)
	} else {
		groups = []*auth.Group{}
	}

	err = query.All(&groups)

	if err != nil {
		return nil, err
	}

	return groups, nil

}

func (m *MgoGroupManager) DeleteGroup(id interface{}) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}
	// TODO: remove this group form user briefgroups too?
	return m.GroupColl.RemoveId(oid)
}

func (m *MgoGroupManager) Close() error {
	m.GroupColl.Database.Session.Close()
	return nil
}

var _ auth.GroupManager = &MgoGroupManager{}
