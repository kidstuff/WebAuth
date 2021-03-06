// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"github.com/gorilla/securecookie"
	"time"
)

type User struct {
	Id           interface{}       `bson:"_id" datastore:"-"`
	Email        string            `bson:"Email"`
	OldPwd       []Password        `bson:"OldPwd" json:",omitempty"`
	Pwd          Password          `bson:"Pwd" json:",omitempty"`
	LastActivity time.Time         `bson:"LastActivity`
	Info         UserInfo          `bson:"Info" datastore:",noindex" json:",omitempty"`
	Privilege    []string          `bson:"Privilege"`
	Approved     bool              `bson:"Approved"`
	ConfirmCodes map[string]string `bson:"ConfirmCodes" datastore:"-" json:",omitempty"`
	BriefGroups  []BriefGroup      `bson:"BriefGroups"`
}

func (u *User) ChangePassword(pwd string) error {
	var err error
	u.OldPwd = append(u.OldPwd, u.Pwd)
	u.Pwd, err = HashPwd(pwd)

	return err
}

func (u *User) ComparePassword(pwd string) error {
	pwdBytes := []byte(pwd)
	tmp := make([]byte, len(pwdBytes)+len(u.Pwd.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, u.Pwd.Salt...)
	if err := bcrypt.CompareHashAndPassword(u.Pwd.Hashed, tmp); err != nil {
		return err
	}

	return nil
}

// ValidConfirmCode valid the code for specific key of the user specify by id.
// Re-generate or delete code for that key if need.
func (u *User) ValidConfirmCode(key, code string, regen, del bool) bool {
	if u.ConfirmCodes[key] == code {
		if del {
			delete(u.ConfirmCodes, key)
		}

		if regen {
			u.ConfirmCodes[key] = base64.URLEncoding.EncodeToString(securecookie.
				GenerateRandomKey(64))
		}

		return true
	}

	return false
}

type Password struct {
	Hashed []byte    `bson:"Hashed"`
	Salt   []byte    `bson:"Salt"`
	InitAt time.Time `bson:"InitAt"`
}

type UserInfo struct {
	FirstName  string    `bson:"FirstName"`
	LastName   string    `bson:"LastName"`
	MiddleName string    `bson:"MiddleName"`
	NickName   string    `bson:"NickName"`
	BirthDay   time.Time `bson:"BirthDay"`
	JoinDay    time.Time `bson:"JoinDay"`
	Address    []Address `bson:"Address"`
	Phone      []string  `bson:"Phone"`
}

type Address struct {
	Country  string `bson:"Country"`
	State    string `bson:"State"`
	City     string `bson:"City"`
	District string `bson:"District"`
	Street   string `bson:"Street"`
}

type UserManager interface {
	// GroupManager returns the GroupManager.
	GroupManager() GroupManager
	// AddUser adds an user to database with email and password;
	// If app is false, the user is waiting to be approved.
	// Implement of this method should valid email, pwd and make sure the user
	// email are unique.
	// It returns an error describes the first issue encountered, if any.
	AddUser(email, pwd string, app bool) (*User, error)
	// AddUserDetail add a User with full detail to database.
	// Implement of this method should valid email, pwd and make sure the user
	// email are unique.
	// It returns an error describes the first issue encountered, if any.
	AddUserDetail(*User) (*User, error)
	// UpdateUserDetail changes detail of the User.
	// It returns an error describes the first issue encountered, if any.
	UpdateUserDetail(*User) error
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
	// Can uses GroupManager to determines if user have privilege to do something.
	Can(user *User, do string) bool
	// Close clean the resources used by the manager if need.
	Close() error
}
