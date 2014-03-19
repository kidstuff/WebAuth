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

type UserManager interface {
	// GroupManager returns the GroupManager.
	GroupManager() GroupManager
	// AddUser adds an user to database with email and password;
	// If app is false, the user is waiting to be approved.
	// It returns an error describes the first issue encountered, if any.
	AddUser(email, pwd string, app bool) (*User, error)
	// AddUserInfo adds an user to database;
	// If app is false, the user is waiting to be approved.
	// It returns an error describes the first issue encountered, if any.
	AddUserDetail(email, pwd string, app bool, info *UserInfo,
		pri map[string]bool) (*User, error)
	// UpdateUserDetail changes detail of user specify by id. Set nill value to
	// keep the current field.
	UpdateUserDetail(id interface{}, app *bool, info *UserInfo,
		pri map[string]bool, code map[string]string, groups []BriefGroup) error
	// ChangePassword changes passowrd of user specify by id.
	ChangePassword(id interface{}, pwd string) error
	// DeleteUser deletes an user from database base on the given id;
	// It returns an error describes the first issue encountered, if any.
	DeleteUser(id interface{}) error
	// FindUser finds the user with the given id;
	// Its returns an ErrNotFound if the user's id was not found.
	FindUser(id interface{}) (*User, error)
	// FindUserByEmail like FindUser but receive an email
	FindUserByEmail(email string) (*User, error)
	// FindAllUser finds and return a slice of user.
	// offsetId, limit define which sub-sequence of matching users to return.
	// Limit take an number of user per page; offsetId take the Id of the last
	// user of the previous page.
	FindAllUser(offsetId interface{}, limit int) ([]*User, error)
	// FindAllUserOline finds and return a slice of current Loged user.
	// See FindAllUser for the usage.
	FindAllUserOnline(offsetId interface{}, limit int) ([]*User, error)
	// ValidateUser validate user base on the current request.
	// It returns the user infomations if the email and password is correct.
	ValidateUser(email, pwd string) (*User, error)
	// GetUser gets the infomations and update the LastActivity of the current
	// loged user by the token (given by Login method);
	// It returns an error describes the first issue encountered, if any.
	GetUser(token string) (*User, error)
	// Login logs user in by given user id.
	// Stay is the duration to keep the user Login state.
	// It returns a token string, use the token to keep track on the user with
	// GetUser or Logout.
	Login(id interface{}, stay time.Duration) (string, error)
	// Logout logs the current user out.
	Logout(token string) error
	// ValidConfirmCode valid the code for specific key of the user specify by id.
	// Re-generate or delete code for that key if need.
	ValidConfirmCode(id interface{}, key, code string, regen, del bool) (bool, error)
	// Can uses GroupManager to determines if user have privilege to do something.
	Can(user *User, do string) bool
	// Close clean the resources used by the manager if need.
	Close() error
}