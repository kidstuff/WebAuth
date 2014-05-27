package mgoauth

import (
	"errors"
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo"
	"net/http"
)

var (
	ErrNotInit = errors.New("mgoauth: package need to be init")
)

type MgoAuthProvider struct {
	DBSess *mgo.Session
	DBName string
}

func (p *MgoAuthProvider) OpenUserMngr(*http.Request) (auth.UserManager, error) {
	if DefaultProvider.DBSess == nil {
		return nil, ErrNotInit
	}
	db := p.DBSess.Clone().DB(p.DBName)
	return NewMgoUserManager(db, NewMgoGroupManager(db)), nil
}

func (p *MgoAuthProvider) OpenGroupMngr(*http.Request) (auth.GroupManager, error) {
	if DefaultProvider.DBSess == nil {
		return nil, ErrNotInit
	}
	return NewMgoGroupManager(p.DBSess.Clone().DB(p.DBName)), nil
}

var DefaultProvider = &MgoAuthProvider{}

func Register(dbsess *mgo.Session, dbname string) {
	DefaultProvider.DBSess = dbsess.Clone()
	DefaultProvider.DBName = dbname
}

func init() {
	auth.Register("mgoauth", DefaultProvider)
}
