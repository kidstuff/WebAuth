// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

type Grouper interface {
	GetId() interface{}
	SetId(interface{}) error
	GetName() string
	GetInfomation() GroupInfo
	GetPrivilege() map[string]bool
}

type BriefGroup struct {
	Id   interface{}
	Name string
}

type Group struct {
	Name      string
	Info      GroupInfo `datastore:",noindex"`
	Privilege map[string]bool
}

func (g *Group) GetName() string {
	return g.Name
}

func (g *Group) GetInfomation() GroupInfo {
	return g.Info
}

func (g *Group) GetPrivilege() map[string]bool {
	return g.Privilege
}

type GroupInfo struct {
	Description string
}
