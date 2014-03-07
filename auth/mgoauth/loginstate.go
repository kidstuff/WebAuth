package mgoauth

import (
	"labix.org/v2/mgo/bson"
	"time"
)

type LoginState struct {
	Exp    time.Time
	UserId bson.ObjectId
	Token  string `bson:"_id"`
}
