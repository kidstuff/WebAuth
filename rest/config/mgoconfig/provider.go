package mgoconfig

import (
	"errors"
	"github.com/kidstuff/WebAuth/rest/config"
	"labix.org/v2/mgo"
	"net/http"
)

var (
	ErrNotInit = errors.New("mgoconfig: package need to be init")
)

type MgoConfiguratorProvider struct {
	DBSess *mgo.Session
	DBName string
}

func (p *MgoConfiguratorProvider) OpenConfigurator(*http.Request) (config.Configurator, error) {
	if DefaultProvider.DBSess == nil {
		return nil, ErrNotInit
	}
	db := p.DBSess.Clone().DB(p.DBName)

	return NewMgoConfig(db), nil
}

var DefaultProvider = &MgoConfiguratorProvider{}

func Register(dbsess *mgo.Session, dbname string) {
	DefaultProvider.DBSess = dbsess.Clone()
	DefaultProvider.DBName = dbname
}

func init() {
	config.ConfiguratorRegister("mgoconfig", DefaultProvider)
}
