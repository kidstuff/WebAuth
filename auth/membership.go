// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package auth provide a interface to easy authorization for your web application.
*/
package auth

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidId       error = errors.New("auth: invalid id")
	ErrInvalidEmail    error = errors.New("auth: invalid email address")
	ErrDuplicateEmail  error = errors.New("auth: duplicate email address")
	ErrInvalidPassword error = errors.New("auth: invalid password")
)

type UserManager interface {
	// SetGroupManager sets GroupManager use for the Can method.
	SetGroupManager(gm GroupManager)
	// AddUser adds an user to database with email and password;
	// If app is false, the user is waiting to be approved.
	// It returns an error describes the first issue encountered, if any.
	AddUser(email, pwd string, app bool) (User, error)
	// AddUserInfo adds an user to database;
	// If app is false, the user is waiting to be approved.
	// It returns an error describes the first issue encountered, if any.
	AddUserDetail(email, pwd string, app bool, info UserInfo,
		pri map[string]bool) (User, error)
	// UpdateInfo changes information of user specify by id.
	UpdateInfo(id interface{}, info UserInfo) error
	// UpdatePrivilege changes privilege of user specify by id.
	UpdatePrivilege(id interface{}, pri map[string]bool) error
	// ChangePassword changes passowrd of user specify by id.
	ChangePassword(id interface{}, pwd string) error
	// DeleteUserByEmail deletes an user from database base on the given id;
	// It returns an error describes the first issue encountered, if any.
	DeleteUser(id interface{}) error
	// GetUser gets the infomations and update the LastActivity of the current
	// Loged user;
	// It returns an error describes the first issue encountered, if any.
	GetUser() (User, error)
	// FindUser finds the user with the given id;
	// Its returns an ErrNotFound if the user's id was not found.
	FindUser(id interface{}) (User, error)
	// FindUserByEmail like FindUser but receive an email
	FindUserByEmail(email string) (User, error)
	// FindAllUser finds and return a slice of user.
	// offsetId, limit define which sub-sequence of matching users to return.
	// Limit take an number of user per page; offsetId take the Id of the last
	// user of the previous page.
	FindAllUser(offsetId interface{}, limit int) ([]User, error)
	// FindAllUserOline finds and return a slice of current Loged user.
	// See FindAllUser for the usage.
	FindAllUserOnline(offsetId interface{}, limit int) ([]User, error)
	// CountUserOnline counts the number of user current Loged.
	// It counts the user that LastActivity+OnlineThreshold<Now.
	CountUserOnline() int
	// ValidateUser validate user email and password.
	// It returns the user infomations if the email and password is correct.
	ValidateUser(r *http.Request) (User, error)
	// Login logs user in by using a session that store user id.
	// Stay take a number of second to keep the user Login state.
	Login(id interface{}, stay int) error
	// Logout logs the current user out.
	Logout() error
	// ValidConfirmCode valid the code for specific key of the user specify by id.
	// Re-generate or delete code for that key if need.
	ValidConfirmCode(id interface{}, key, code string, regen, del bool) (bool, error)
	// Can uses GroupManager to determines if user have privilege to do something.
	Can(user User, do string) bool
}
