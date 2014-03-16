// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package auth provide a interface to easy authorization for your web application.
*/
package auth

import (
	"errors"
)

var (
	ErrInvalidId       = errors.New("auth: invalid id")
	ErrInvalidEmail    = errors.New("auth: invalid email address")
	ErrDuplicateEmail  = errors.New("auth: duplicate email address")
	ErrInvalidPassword = errors.New("auth: invalid password")
	ErrNotLogged       = errors.New("auth: no login user found")
	ErrNoProvider      = errors.New("auth: no provider found")
)

type AuthProvider interface {
	OpenUserMngr() (UserManager, error)
	OpenGroupMngr() (GroupManager, error)
}

var (
	mapProvider  = make(map[string]AuthProvider)
	lastProvider AuthProvider
)

func Register(name string, p AuthProvider) error {
	_, ok := mapProvider[name]
	if ok {
		return ErrNoProvider
	}

	mapProvider[name] = p
	lastProvider = p
	return nil
}

func GetProvider(name string) (AuthProvider, error) {
	p, ok := mapProvider[name]
	if !ok {
		return nil, ErrNoProvider
	}

	return p, nil
}

// Provider returns the last provider added. It will panic if there's no one.
func Provider() AuthProvider {
	if lastProvider == nil {
		panic(ErrNoProvider.Error())
	}
	return lastProvider
}
