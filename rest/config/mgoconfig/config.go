package mgoconfig

import (
	"labix.org/v2/mgo"
)

type configObj struct {
	Key string `bson:"_id"`
	Val string
}

type MgoConfig struct {
	ConfigColl *mgo.Collection
}

func NewMgoConfig(db *mgo.Database) *MgoConfig {
	return &MgoConfig{db.C("mgoconfig")}
}

func (c *MgoConfig) Set(key, val string) error {
	_, err := c.ConfigColl.UpsertId(key, &configObj{key, val})
	return err
}

func (c *MgoConfig) Get(key string) (string, error) {
	var result configObj
	err := c.ConfigColl.FindId(key).One(&result)

	return result.Val, err
}

func (c *MgoConfig) Close() error {
	c.ConfigColl.Database.Session.Close()
	return nil
}
