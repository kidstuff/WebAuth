// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"time"
)

type User interface {
	GetId() interface{}
	SetId(interface{}) error
	GetEmail() string
	GetPassword() Password
	GetOldPassword() Password
	GetInfomation() UserInfo
	GetPrivilege() map[string]bool
	IsApproved() bool
	GetConfirmCodes() map[string]string
	GetBriefGroups() []BriefGroup
}

type Account struct {
	Email        string
	OldPwd       Password
	Pwd          Password
	LastActivity time.Time
	Info         UserInfo `datastore:",noindex"`
	Privilege    map[string]bool
	Approved     bool
	ConfirmCodes map[string]string
	BriefGroups  []BriefGroup
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetPassword() Password {
	return a.Pwd
}

func (a *Account) GetOldPassword() Password {
	return a.OldPwd
}

func (a *Account) GetInfomation() UserInfo {
	return a.Info
}

func (a *Account) GetPrivilege() map[string]bool {
	return a.Privilege
}

func (a *Account) IsApproved() bool {
	return a.Approved
}

func (a *Account) GetConfirmCodes() map[string]string {
	return a.ConfirmCodes
}

func (a *Account) GetBriefGroups() []BriefGroup {
	return a.BriefGroups
}

type Password struct {
	Hashed []byte
	Salt   []byte
	InitAt time.Time
}

type UserInfo struct {
	FirstName  string
	LastName   string
	MiddleName string
	NickName   string
	BirthDay   time.Time
	JoinDay    time.Time
	Address    []Address
	Phone      []string
}

type Address struct {
	Country  string
	State    string
	City     string
	District string
	Street   string
}
