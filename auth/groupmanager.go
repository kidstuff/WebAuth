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

type GroupManager interface {
	// AddGroupDetail adds a group with full detail to database.
	AddGroupDetail(name string, info GroupInfo, pri map[string]bool) (Grouper,
		error)
	// UpdateInfo updates group infomation specific by id.
	UpdateInfo(id interface{}, info GroupInfo) error
	// UpdatePrivilege updates group privilege specific by id.
	UpdatePrivilege(id interface{}, pri map[string]bool) error
	// FindGroup find the group specific by id.
	FindGroup(id interface{}) (Grouper, error)
	// FindSomeGroup find and return a slice of group specific by thier id.
	FindSomeGroup(id ...interface{}) ([]Grouper, error)
	// FindAllGroup finds and return a slice of group. offsetId define which
	// sub-sequence of matching groups to be returned.
	FindAllGroup(offsetId interface{}, limit int) ([]Grouper, error)
}
