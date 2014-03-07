// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"time"
)

type User struct {
	Id           interface{} `bson:"_id"`
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
