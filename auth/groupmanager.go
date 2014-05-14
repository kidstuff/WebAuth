// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"errors"
)

var (
	ErrDuplicateName = errors.New("auth: duplicate Group Name")
)

type BriefGroup struct {
	Id   interface{} `bson:"_id"`
	Name string      `bson:"Name"`
}

type Group struct {
	BriefGroup `bson:"BriefGroup,inline"`
	Info       GroupInfo `bson:"Info" datastore:",noindex"`
	Privilege  []string  `bson:"Privilege"`
}

type GroupInfo struct {
	Description string `bson:"Description"`
}

type GroupManager interface {
	// AddGroupDetail adds a group with full detail to database.
	AddGroupDetail(name string, info *GroupInfo, pri []string) (*Group,
		error)
	// UpdateGroupDetail updates group detail specific by id.
	UpdateGroupDetail(id interface{}, info *GroupInfo, pri []string) error
	// FindGroup find the group specific by id.
	FindGroup(id interface{}) (*Group, error)
	// FindSomeGroup find and return a slice of group specific by thier id.
	FindSomeGroup(id ...interface{}) ([]*Group, error)
	// FindAllGroup finds and return a slice of group. offsetId define which
	// sub-sequence of matching groups to be returned.
	FindAllGroup(offsetId interface{}, limit int) ([]*Group, error)
	// DeleteGroup deletes a group from database base on the given id;
	// It returns an error describes the first issue encountered, if any.
	DeleteGroup(id interface{}) error
	// Close clean the resources used by the manager if need.
	Close() error
}
